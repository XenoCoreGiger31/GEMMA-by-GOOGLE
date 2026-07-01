import re
from pathlib import Path
import yaml

SKILLS_DIR = Path.home() / "security-agent" / "skills"

def _parse_skill_file(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    match = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", text, re.DOTALL)
    if not match:
        raise ValueError(f"NO MATCH - aborting: {path} missing frontmatter")
    frontmatter, body = match.groups()
    meta = yaml.safe_load(frontmatter)
    return {"name": meta["name"], "description": meta["description"], "body": body.strip(), "path": path}

def list_skills(category: str | None = None) -> list[dict]:
    base = SKILLS_DIR / category if category else SKILLS_DIR
    return [_parse_skill_file(p) for p in base.rglob("*.md")]

def load_skills(names: list[str]) -> str:
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
