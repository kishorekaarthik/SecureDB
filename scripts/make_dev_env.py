"""Create .env and .env.test from the examples with random local-only DB passwords.

Both files share the same passwords because they use the same two roles.
Safe to re-run: does nothing if both files already exist.
"""

import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {".env": ".env.example", ".env.test": ".env.test.example"}


def main() -> None:
    existing = [name for name in TARGETS if (ROOT / name).exists()]
    if len(existing) == len(TARGETS):
        print(".env and .env.test already exist; nothing to do.")
        return
    if existing:
        raise SystemExit(
            f"Only {existing[0]} exists. Delete it and re-run so both files share passwords."
        )
    owner_pw = secrets.token_urlsafe(24)
    app_pw = secrets.token_urlsafe(24)
    for target, template in TARGETS.items():
        text = (ROOT / template).read_text(encoding="utf-8")
        text = text.replace("CHANGE_ME_OWNER", owner_pw).replace("CHANGE_ME_APP", app_pw)
        (ROOT / target).write_text(text, encoding="utf-8")
        print(f"Wrote {target}")


if __name__ == "__main__":
    main()
