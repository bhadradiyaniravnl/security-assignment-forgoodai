"""git-lab: stands in for GitHub. Seeds bare repos from /app/demo-repo and serves them
read-only over git:// to the control plane (the only client its network policy admits).
Scoped tokens and push (GitHub App style) are designed, not built (DESIGN §7)."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

REPOS = os.environ.get("GIT_LAB_ROOT", "/repos")
SEEDS = {   # repo -> (base, overlay). Overlays add the prompt-injection fixtures.
    "demo/app": ("/app/demo-repo", None),
    "demo/app-injected": ("/app/demo-repo", "/app/fixtures/injections/paste"),
    "demo/app-injected-sink": ("/app/demo-repo", "/app/fixtures/injections/sink"),
}
ENV = {**os.environ, "GIT_AUTHOR_NAME": "git-lab", "GIT_AUTHOR_EMAIL": "git-lab@lab.invalid",
       "GIT_COMMITTER_NAME": "git-lab", "GIT_COMMITTER_EMAIL": "git-lab@lab.invalid", "HOME": "/tmp"}


def git(*args: str, cwd: str | None = None) -> None:
    subprocess.run(["git", *args], cwd=cwd, env=ENV, check=True, capture_output=True)


def seed(name: str, src: str, overlay: str | None = None) -> None:
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
