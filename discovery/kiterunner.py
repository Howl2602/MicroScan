import subprocess
import json



result = subprocess.run(
    [
        r".\discovery\kr.exe",
        "scan",
        "localhost:8085",
        "-A=apiroutes-260227:500",
        "-x", "3",
        "-j", "1",
        "-o", "json"
        
    ],
    capture_output=True,
    text=True
    
)

res = [];


for line in result.stdout.splitlines():
    print(line)
    data = json.loads(line)
    res.append(data);
    print(data["method"])
    print(data["target"])
    print(data["path"])
    print(data["responses"][0]["uri"])
    print(data["responses"][0]["sc"])
    print(data["responses"][0]["len"])
    
    
    
