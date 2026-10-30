"""git-lab: lab stand-in for a git host. Seeds bare repos from /app/samples/slugkit (plus the
prompt-injection fixture overlays) and serves them read-only over git:// (git daemon, no auth) to
the control plane, the only client its network policy admits. Sandboxes never reach it.

Not an enforcement point: access control is the network policy. git-lab has no per-session tokens
or push on purpose; the real-GitHub path, with scoped App tokens and draft PRs, is credproxy/github.py."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

REPOS = os.environ.get("GIT_LAB_ROOT", "/repos")
SEEDS = {   # repo -> (base, overlay). Overlays add the prompt-injection fixtures.
    "demo/app": ("/app/samples/slugkit", None),
    "demo/app-injected": ("/app/samples/slugkit", "/app/fixtures/injections/paste"),
    "demo/app-injected-sink": ("/app/samples/slugkit", "/app/fixtures/injections/sink"),
}
ENV = {**os.environ, "GIT_AUTHOR_NAME": "git-lab", "GIT_AUTHOR_EMAIL": "git-lab@lab.invalid",
       "GIT_COMMITTER_NAME": "git-lab", "GIT_COMMITTER_EMAIL": "git-lab@lab.invalid", "HOME": "/tmp"}


def git(*args: str, cwd: str | None = None) -> None:
    """Run git with a fixed lab identity; raises on failure."""
    subprocess.run(["git", *args], cwd=cwd, env=ENV, check=True, capture_output=True)


def seed(name: str, src: str, overlay: str | None = None) -> None:
    """Create bare repo <name>.git from src (+ overlay) as a single commit; no-op if it exists."""
    bare = os.path.join(REPOS, f"{name}.git")
    if os.path.exists(bare):
        return
    work = tempfile.mkdtemp()
    shutil.copytree(src, work, dirs_exist_ok=True)
    if overlay:
        shutil.copytree(overlay, work, dirs_exist_ok=True)
    git("init", "-q", "-b", "main", cwd=work)
    git("add", "-A", cwd=work)
    git("commit", "-q", "-m", f"seed {name}", cwd=work)
    os.makedirs(os.path.dirname(bare), exist_ok=True)
    git("clone", "-q", "--bare", work, bare)
    shutil.rmtree(work)
    print(f"seeded {name}", flush=True)


if __name__ == "__main__":
    for name, (src, overlay) in SEEDS.items():
        seed(name, src, overlay)
    os.execvpe("git", ["git", "daemon", "--export-all", f"--base-path={REPOS}", "--reuseaddr",
                       "--port=8080", "--listen=0.0.0.0", "--informative-errors", REPOS], ENV)
