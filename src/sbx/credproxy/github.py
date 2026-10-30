"""GitHub App operations, performed entirely inside credproxy.

Tokens are installation tokens minted per operation: scoped to one repository, carrying only the
permissions that operation needs, used once and revoked immediately. They are never returned to a
caller, never written to disk (git gets them through an in-memory http.extraHeader), and never
reach the sandbox. Callers get a tarball (clone) or a PR URL (publish).

Trust: credproxy/app.py has already checked the caller (control-plane key) and the spec's grant.
This module does not trust the agent's diff: protected paths, symlinks and submodules are refused,
first on the diff text and then, authoritatively, on what git actually staged.
"""
from __future__ import annotations

import base64
import io
import os
import re
import subprocess
import tarfile
import tempfile
import time

import httpx
import jwt

API = "https://api.github.com"
APP_ID = os.environ.get("GITHUB_APP_ID", "")
KEY_PATH = os.environ.get("GITHUB_APP_KEY", "/secrets/github/app.pem")
REPO_RE = re.compile(r"^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$")
GIT_ENV = {"HOME": "/tmp", "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
           "GIT_AUTHOR_NAME": "sbx-agent-platform", "GIT_AUTHOR_EMAIL": "sbx-agent-platform@users.noreply.github.com",
           "GIT_COMMITTER_NAME": "sbx-agent-platform", "GIT_COMMITTER_EMAIL": "sbx-agent-platform@users.noreply.github.com"}


class GitHubError(Exception):
    """A GitHub or git failure; the message is safe to return (tokens are redacted)."""


def enabled() -> bool:
    """True when a GitHub App ID and private key are configured."""
    return bool(APP_ID) and os.path.exists(KEY_PATH)


def _app_jwt() -> str:
    """Short-lived JWT that authenticates as the App itself (only used to mint installation tokens)."""
    now = int(time.time())
    return jwt.encode({"iat": now - 60, "exp": now + 540, "iss": APP_ID}, open(KEY_PATH).read(), algorithm="RS256")


def _github_api(method: str, path: str, token: str, bearer: bool = True, **kw) -> httpx.Response:
    """Call the GitHub REST API: Bearer for the App JWT, `token` scheme for installation tokens."""
    auth = f"Bearer {token}" if bearer else f"token {token}"
    return httpx.request(method, API + path, timeout=30, **kw,
                         headers={"Authorization": auth, "Accept": "application/vnd.github+json",
                                  "X-GitHub-Api-Version": "2022-11-28"})


class Token:
    """Context manager: mint a repo-scoped installation token, revoke it on exit."""

    def __init__(self, repo: str, permissions: dict):
        if not REPO_RE.match(repo):
            raise GitHubError("bad repo name")
        self.repo, self.permissions = repo, permissions
        self.value = ""
        self.meta: dict = {}

    def __enter__(self) -> "Token":
        app = _app_jwt()
        r = _github_api("GET", f"/repos/{self.repo}/installation", app)
        if r.status_code != 200:
            raise GitHubError(f"app not installed on {self.repo} ({r.status_code})")
        installation_id = r.json()["id"]
        r = _github_api("POST", f"/app/installations/{installation_id}/access_tokens", app,
                json={"repositories": [self.repo.split("/", 1)[1]], "permissions": self.permissions})
        if r.status_code != 201:
            raise GitHubError(f"token mint failed ({r.status_code}): {r.text[:200]}")
        body = r.json()
        self.value = body["token"]
        self.meta = {"repo": self.repo, "permissions": body.get("permissions"), "expires_at": body.get("expires_at"),
                     "installation_id": installation_id}
        return self

    def __exit__(self, *exc) -> None:
        if self.value:
            r = _github_api("DELETE", "/installation/token", self.value, bearer=False)
            self.meta["revoked"] = r.status_code == 204
            self.value = ""

    def git_header(self) -> str:
        """`git -c` value that sends the token as an HTTP header, so it never lands in .git/config."""
        basic = base64.b64encode(f"x-access-token:{self.value}".encode()).decode()
        return f"http.https://github.com/.extraheader=AUTHORIZATION: basic {basic}"


def _git(args: list[str], cwd: str | None = None, token: Token | None = None, stdin: str | None = None) -> str:
    """Run git with an isolated config; returns stdout, raises GitHubError with the token redacted."""
    cmd = ["git"] + (["-c", token.git_header()] if token else []) + args
    proc = subprocess.run(cmd, cwd=cwd, env=GIT_ENV, input=stdin, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout).replace(token.value, "***") if token and token.value else (proc.stderr or proc.stdout)
        raise GitHubError(f"git {args[0]} failed: {msg.strip()[:300]}")
    return proc.stdout


def clone(repo: str, ref: str = "main") -> tuple[bytes, dict]:
    """Shallow clone with a contents:read token. Returns (tar.gz bytes, token metadata)."""
    with Token(repo, {"contents": "read"}) as tok, tempfile.TemporaryDirectory() as tmp:
        dest = os.path.join(tmp, "repo")
        _git(["clone", "-q", "--depth", "1", "--branch", ref, f"https://github.com/{repo}.git", dest], token=tok)
        _git(["remote", "set-url", "origin", f"https://github.com/{repo}.git"], cwd=dest)
        head = _git(["rev-parse", "HEAD"], cwd=dest).strip()
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            tar.add(dest, arcname="repo")
    return buf.getvalue(), {**tok.meta, "commit": head}


def changed_paths(diff: str) -> list[str]:
    """Paths named in the diff's `diff --git` headers (a first, cheap filter; see _verify_staged_paths)."""
    paths = set()
    for line in diff.splitlines():
        m = re.match(r"^diff --git a/(.+?) b/(.+)$", line)
        if m:
            paths.update(m.groups())
    return sorted(paths)


def _verify_staged_paths(dest: str, protected: list[str]) -> list[str]:
    """Refuse staged changes to protected paths, symlinks or submodules; return the staged paths."""
    raw = _git(["-c", "core.quotepath=off", "diff", "--cached", "--raw", "-z", "--no-renames"], cwd=dest)
    fields = raw.split("\0")
    paths, bad = [], []
    i = 0
    while i < len(fields) - 1:
        meta, path = fields[i], fields[i + 1]
        i += 2
        if not meta.startswith(":"):
            continue
        old_mode, new_mode = meta[1:].split()[:2]
        paths.append(path)
        if any(path == prefix.rstrip("/") or path.startswith(prefix) for prefix in protected):
            bad.append(f"{path} (protected)")
        if new_mode in ("120000", "160000") or old_mode in ("120000", "160000"):     # symlink, gitlink
            bad.append(f"{path} (symlink/submodule)")
    if bad:
        raise GitHubError(f"diff touches protected paths: {bad}")
    if not paths:
        raise GitHubError("empty diff")
    return sorted(paths)


def publish(repo: str, base: str, branch: str, diff: str, title: str, body: str,
            protected: list[str], draft: bool = True) -> dict:
    """Applies the agent's diff to a fresh clone of `base`, pushes `branch`, opens a PR (draft by default)."""
    paths = changed_paths(diff)
    if not paths:
        raise GitHubError("empty diff")
    blocked = [p for p in paths
               if any(p == prefix.rstrip("/") or p.startswith(prefix) for prefix in protected) or "/../" in f"/{p}"]
    if blocked:
        raise GitHubError(f"diff touches protected paths: {blocked}")
    with Token(repo, {"contents": "write", "pull_requests": "write"}) as tok, tempfile.TemporaryDirectory() as tmp:
        dest = os.path.join(tmp, "repo")
        _git(["clone", "-q", "--depth", "1", "--branch", base, f"https://github.com/{repo}.git", dest], token=tok)
        _git(["checkout", "-q", "-b", branch], cwd=dest)
        _git(["apply", "--whitespace=nowarn", "-"], cwd=dest, stdin=diff)
        _git(["add", "-A"], cwd=dest)
        # Authoritative check on what git actually staged (paths and modes), not on the diff text:
        # the text can hide paths (quoting, header-less hunks) that `git apply` still writes.
        paths = _verify_staged_paths(dest, protected)
        _git(["commit", "-q", "-m", title], cwd=dest)
        commit = _git(["rev-parse", "HEAD"], cwd=dest).strip()
        _git(["push", "-q", "origin", f"HEAD:refs/heads/{branch}"], cwd=dest, token=tok)
        r = _github_api("POST", f"/repos/{repo}/pulls", tok.value, bearer=False,
                        json={"title": title, "head": branch, "base": base, "body": body, "draft": draft})
        if r.status_code == 422 and draft and "draft" in r.text.lower():
            # Draft PRs need a paid plan on private repos: fall back to a clearly marked normal PR.
            r = _github_api("POST", f"/repos/{repo}/pulls", tok.value, bearer=False,
                            json={"title": f"[draft] {title}", "head": branch, "base": base, "body": body, "draft": False})
        if r.status_code != 201:
            raise GitHubError(f"PR create failed ({r.status_code}): {r.text[:200]}")
        pr = r.json()
    return {"pr_url": pr["html_url"], "pr_number": pr["number"], "branch": branch, "commit": commit,
            "paths": paths, "token": tok.meta}
