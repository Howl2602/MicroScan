import sys
from pathlib import Path

from fastapi import FastAPI
import httpx

from discovery.models import Discovery

app = FastAPI()


@app.get("/")
def home():
    return {"message": "app is running"}


@app.get("/scan")
def scan(target: str, num: int = 1000):
    discovery = Discovery()
    results = discovery.discover(target, num)
    return {"results": results}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)

