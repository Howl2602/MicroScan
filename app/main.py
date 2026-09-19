from fastapi import FastAPI
import httpx

app = FastAPI()


@app.get("/")
def home():
    return {
        "message": "app is running"
        
    }


@app.get("/scan")
def scan(target: str):
    
    try:
        response = httpx.get(target, timeout=5.0)
        
    except httpx.RequestError as exc:
          
            return {
                "target": target,
                "status": None,
                "reachable": False,
                "response_time": None,
                "error": str(exc)
                
            }

    try:
        message = response.json()
        
    except Exception:
        message = response.text
    
    
    return {
        "target": target, 
        "status": response.status_code,
        "reachable": True,
        "response_time": response.elapsed.total_seconds(),
        "message": message
        
    }