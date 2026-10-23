import json
import subprocess
from pathlib import Path
from urllib.parse import urlsplit


class KiteRunner:
    def __init__(self):
        base_dir = Path(__file__).resolve().parent
        self.executable = self._resolve_executable(base_dir)

    def _resolve_executable(self, base_dir):
        candidates = [
            base_dir / "kr.exe",
            base_dir / "kr",
            base_dir.parent / "kr.exe",
            base_dir.parent / "kr",
        ]
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
        return str(base_dir / "kr.exe")

    def _normalize_target(self, target):
        candidate = (target or "").strip()
        if not candidate:
            raise ValueError("Target is required.")
        if any(ch.isspace() for ch in candidate):
            raise ValueError("Target must not contain whitespace.")

        if "//" not in candidate and ":" in candidate and not candidate.startswith(("http://", "https://")):
            candidate = f"http://{candidate}"
        if "://" not in candidate:
            candidate = f"http://{candidate}"

        parsed = urlsplit(candidate)
        if parsed.scheme not in {"http", "https"} or not (parsed.netloc or parsed.path):
            raise ValueError("Target must be a valid http:// or https:// URL.")

        host = parsed.netloc or parsed.path.split("/", 1)[0]
        if not host:
            raise ValueError("Target is missing a host or port.")
        return host

    def _parse_json_lines(self, output):
        results = []
        seen = set()

        for line in output.splitlines():
            text = line.strip()
            if not text:
                continue
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                continue

            if not isinstance(data, dict):
                continue

            route = data.get("path") or data.get("target")
            if not route:
                continue

            key = (
                data.get("method"),
                route,
                data.get("target"),
                data.get("status"),
                data.get("status_code"),
            )
            if key in seen:
                continue
            seen.add(key)
            results.append(data)

        return results

    def kiterunner_scan(self, target, num):
        normalized_target = self._normalize_target(target)
        limit = max(1, min(int(num or 1000), 5000))

        command = [
            self.executable,
            "scan",
            normalized_target,
            f"-A=apiroutes-260227:{limit}",
            "-x", "3",
            "-j", "1",
            "-q",
            "-o", "json",
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=90,
                check=False,
            )
        except FileNotFoundError as exc:
            raise FileNotFoundError(f"Kiterunner executable not found: {self.executable}") from exc
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(f"Kiterunner timed out while scanning {normalized_target}") from exc

        output_text = "\n".join(part for part in [result.stdout, result.stderr] if part)
        results = self._parse_json_lines(output_text)

        if not results and result.returncode not in (0, 1):
            raise RuntimeError(
                f"Kiterunner failed for {normalized_target}: {result.stderr.strip() or result.stdout.strip() or 'unknown error'}"
            )

        return results
