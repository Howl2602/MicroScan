import sys
from pathlib import Path

from fastapi import FastAPI
import httpx

from fastapi.middleware.cors import CORSMiddleware

from discovery.models import Discovery
from module.modules import Modules 

app = FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {"message": "app is running"}


@app.get("/scan")
def scan(target: str, num: int = 10000):
    # if "://" not in target:
    #     target = "http://" + target

    discovery = Discovery()
    results = discovery.discover(target, num)

    #jwt = Modules().getJwt("http://localhost:8000/login")

    return {
        "target": target,
        "results": results,
        #"jwt": jwt
    }


if __name__ == "__main__":
    
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)

