"""
Markdown "skill" loader for the HALO agent.

A skill is a Markdown playbook with a YAML frontmatter header (name +
description) and a body. This module discovers them under ./skills, loads
selected ones, and picks the ones most relevant to a goal so the agent loop
can inject just-in-time guidance into the model prompt.
"""

import os
import re
from pathlib import Path
import yaml

# Ship-with-the-repo skills live in ./skills next to this file. Override the
# location with HALO_SKILLS_DIR if you keep playbooks elsewhere.
DEFAULT_SKILLS_DIR = Path(__file__).resolve().parent / "skills"
SKILLS_DIR = Path(os.environ.get("HALO_SKILLS_DIR", str(DEFAULT_SKILLS_DIR)))

def _parse_skill_file(path: Path) -> dict:
    """Parse one skill file into its name, description, body, and path."""
    text = path.read_text(encoding="utf-8")
    match = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", text, re.DOTALL)
    if not match:
        raise ValueError(f"NO MATCH - aborting: {path} missing frontmatter")
    frontmatter, body = match.groups()
    meta = yaml.safe_load(frontmatter)
    return {"name": meta["name"], "description": meta["description"], "body": body.strip(), "path": path}

def list_skills(category: str | None = None) -> list[dict]:
    """Parse every skill under SKILLS_DIR (optionally one category subdir)."""
    base = SKILLS_DIR / category if category else SKILLS_DIR
    return [_parse_skill_file(p) for p in base.rglob("*.md")]

def load_skills(names: list[str]) -> str:
    """Return the bodies of the named skills, joined by a Markdown separator."""
    all_skills = list_skills()
    by_name = {s["name"]: s for s in all_skills}
    selected = []
    for n in names:
        if n not in by_name:
            print(f"NO MATCH - aborting: skill '{n}' not found")
            continue
        selected.append(by_name[n]["body"])
    return "\n\n---\n\n".join(selected)

def select_relevant_skills(text: str, max_skills: int = 3) -> list[str]:
    """Pick skill names whose name or description keywords appear in the given text."""
    text_lower = text.lower()
    matches = []
    for skill in list_skills():
        keywords = skill["name"].replace("-", " ").split() + skill["description"].lower().split()
        if any(kw in text_lower for kw in keywords if len(kw) > 3):
            matches.append(skill["name"])
        if len(matches) >= max_skills:
            break
    return matches
