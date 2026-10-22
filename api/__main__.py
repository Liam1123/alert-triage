"""Run the app: python -m api

Binds to 127.0.0.1:8000, as `uvicorn api.main:app` does. With PUBLIC_DEMO=1
it binds to 0.0.0.0 and $PORT instead, the way a host like Render expects.
Local development is unchanged: `uvicorn api.main:app --reload` still works.
"""

import os

import uvicorn

from api.main import public_demo


def bind() -> tuple[str, int]:
    if public_demo():
        return "0.0.0.0", int(os.environ.get("PORT", "8000"))  # The deploy has to listen publicly.
    return "127.0.0.1", 8000


if __name__ == "__main__":
    host, port = bind()
    uvicorn.run("api.main:app", host=host, port=port)
