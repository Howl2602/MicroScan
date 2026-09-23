import json
import subprocess


class KiteRunner:
    def kiterunner_scan(self, target, num):
        result = subprocess.run(
            [
                r".\discovery\kr.exe",
                "scan",
                target,
                f"-A=apiroutes-260227:{num}",
                "-x", "3",
                "-j", "1",
                "-o", "json",
                
            ],
            capture_output=True,
            text=True,
        )

        res = []

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                if isinstance(data, dict):
                    res.append(data)
                    
                    
            except json.JSONDecodeError as exc:
                print(f"Invalid JSON line: {line}\n{exc}")



        return res
