import httpx

class Signin:
    def signup(self, target):
        payload = {
            "username": "userA",
            "password": "123456"
            
        }
        
        response = httpx.post(target, json=payload, timeout=10)
        if response.status_code in (200, 201):
            
            return 1;
        else:
            return 0;

        
        
    def signin(self, target: str):
        if "://" not in target:
            target = "http://" + target

        payload = {
            "username": "userA",
            "password": "123456"
        }

        response = httpx.post(target, json=payload, timeout=10)
        data = response.json()

        token = data.get("access_token") or data.get("token") or data.get("jwt") or data.get("bearer")

        return token
        
        
        