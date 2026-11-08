"""Start the EDR server (API + dashboard). Settings come from environment variables or a .env file (see .env.example)."""
import os
from pathlib import Path


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


load_dotenv(Path(__file__).parent / ".env")

import uvicorn  # noqa: E402
from server.app.main import create_app  # noqa: E402

if __name__ == "__main__":
    uvicorn.run(create_app(), host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8000")))
