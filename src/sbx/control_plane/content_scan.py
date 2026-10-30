"""Pre-run scan of repository content for instruction-like text aimed at coding agents.

Not a prevention control (the boundary is structural); it exists because agents rarely tell the
user about injected instructions they saw (0 of 24 harness trials did). Findings go to evidence, a
low-severity alert and the PR body, so the human reviewer is warned. Expect false positives on
repos that legitimately document agent workflows; keep rules specific and the output reviewable.
"""
from __future__ import annotations

import os
import re

MAX_FILE = 256 * 1024
MAX_FINDINGS = 50
RULES = [
    ("agent_directive", re.compile(r"(?i)\b(note|instructions?|attention|reminder)\s+(for|to)\s+"
                                   r"(automated|ai|coding|llm)\s+(coding\s+)?(assistants?|agents?|models?)")),
    ("agent_addressed", re.compile(r"(?i)\b(ai|llm|automated|coding)\s+(assistants?|agents?)\b[^\n]{0,80}"
                                   r"\b(must|should|required|always|before)\b")),
    ("instruction_override", re.compile(r"(?i)\bignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+"
                                        r"(instructions|rules|directions)")),
    ("concealment", re.compile(r"(?i)\b(do not|don't|no need to|never)\s+(mention|tell|report|include|disclose)")),
    ("secret_send_command", re.compile(r"(?i)\b(curl|wget|nc|ncat|http|httpie|python3?\s+-c)\b[^\n]{0,120}"
                                       r"(@\.env|\.env\b|--data-binary\s+@|-d\s+@|--upload-file)")),
    ("pipe_to_shell", re.compile(r"(?i)\b(curl|wget)\b[^\n|]{0,200}\|\s*(ba|z)?sh\b")),
    ("hidden_characters", re.compile("[​-‏‪-‮⁦-⁩]")),
    ("html_comment_to_agent", re.compile(r"(?is)<!--[^>]{0,400}\b(assistant|agent|llm|ai)\b[^>]{0,400}-->")),
]


def scan(root: str) -> list[dict]:
    findings: list[dict] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            if rel == ".env" or os.path.islink(path):
                continue
            try:
                if os.path.getsize(path) > MAX_FILE:
                    continue
                with open(path, "rb") as f:
                    raw = f.read()
            except OSError:
                continue
            if b"\0" in raw[:4096]:
                continue                                    # binary
            text = raw.decode("utf-8", errors="replace")
            for rule, rx in RULES:
                for m in rx.finditer(text):
                    line = text.count("\n", 0, m.start()) + 1
                    excerpt = m.group(0)
                    if rule == "hidden_characters":
                        excerpt = f"U+{ord(excerpt):04X}"
                    findings.append({"path": rel, "line": line, "rule": rule,
                                     "excerpt": excerpt.replace("\n", " ")[:160]})
                    if len(findings) >= MAX_FINDINGS:
                        return findings
    return findings
