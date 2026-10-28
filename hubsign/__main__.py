"""`hubsign` CLI: run the server."""

from __future__ import annotations

import argparse

import uvicorn


def main() -> None:
    p = argparse.ArgumentParser(prog="hubsign")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    a = p.parse_args()
    uvicorn.run("hubsign.api:create_app", factory=True, host=a.host, port=a.port)


if __name__ == "__main__":
    main()
