import json
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit


class KiteRunner:
    MAX_SEEDS = 50
    MAX_SEED_SCAN_ROUTES = 100
    SEED_SCAN_TIMEOUT_SECONDS = 45

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

    @staticmethod
    def _failure_diagnostic(stderr, stdout):
        diagnostic = " ".join((stderr or "").split())
        if diagnostic:
            return diagnostic[:500]
        return f"no stderr; stdout_bytes={len((stdout or '').encode('utf-8'))}"

    def kiterunner_scan(
        self, target, num, return_outcome=False, timeout_seconds=None
    ):
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
                timeout=(
                    90
                    if timeout_seconds is None
                    else max(5, min(int(timeout_seconds), 90))
                ),
                check=False,
            )
        except FileNotFoundError as exc:
            raise FileNotFoundError(f"Kiterunner executable not found: {self.executable}") from exc
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(f"Kiterunner timed out while scanning {normalized_target}") from exc

        output_text = "\n".join(part for part in [result.stdout, result.stderr] if part)
        results = self._parse_json_lines(output_text)

        if (
            result.returncode not in (0, 1)
            and (return_outcome or not results)
        ):
            raise RuntimeError(
                f"Kiterunner failed for {normalized_target} "
                f"(exit_code={result.returncode}, command={result.args!r}): "
                f"{self._failure_diagnostic(result.stderr, result.stdout)}"
            )

        if return_outcome:
            return {
                "target": normalized_target,
                "command": command,
                "exit_code": result.returncode,
                "result_count": len(results),
                "results": results,
            }
        return results

    def kiterunner_seed_scan(
        self, target, seed_paths, num=100, timeout_seconds=None
    ):
        normalized_target = self._normalize_target(target)
        static_paths = []
        seen = set()
        for value in seed_paths:
            if not isinstance(value, str):
                continue
            path = value.strip()
            if (
                not path.startswith("/")
                or path.startswith("//")
                or any(character.isspace() for character in path)
                or "\\" in path
                or "?" in path
                or "#" in path
                or "${" in path
                or re.search(r"\{[^/}]+\}|(?<![\w]):[A-Za-z_$][\w$]*(?=/|$)", path)
            ):
                continue
            if path in seen:
                continue
            seen.add(path)
            static_paths.append(path)
            if len(static_paths) >= self.MAX_SEEDS:
                break

        if not static_paths:
            return {
                "target": normalized_target,
                "seed_count": 0,
                "exit_code": None,
                "result_count": 0,
                "results": [],
                "command": [],
                "stdout": "",
                "stderr": "",
            }

        route_limit = max(1, min(int(num or self.MAX_SEED_SCAN_ROUTES), self.MAX_SEED_SCAN_ROUTES))
        with tempfile.TemporaryDirectory(prefix="microscan-kiterunner-seeds-") as temp_dir:
            seed_text = Path(temp_dir) / "seeds.txt"
            seed_wordlist = Path(temp_dir) / "seeds.kite"
            seed_text.write_text("\n".join(static_paths) + "\n", encoding="utf-8")
            try:
                compiled = subprocess.run(
                    [
                        self.executable,
                        "kb",
                        "convert",
                        str(seed_text),
                        str(seed_wordlist),
                        "-q",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
            except FileNotFoundError as exc:
                raise FileNotFoundError(
                    f"Kiterunner executable not found: {self.executable}"
                ) from exc
            except subprocess.TimeoutExpired as exc:
                raise TimeoutError(
                    "Kiterunner seed wordlist compilation timed out "
                    f"(command={exc.cmd!r})."
                ) from exc
            if compiled.returncode != 0 or not seed_wordlist.is_file():
                diagnostic = self._failure_diagnostic(
                    compiled.stderr, compiled.stdout
                )
                raise RuntimeError(
                    "Kiterunner seed wordlist compilation failed "
                    f"(exit_code={compiled.returncode}, command={compiled.args!r})"
                    f": {diagnostic}"
                )

            command = [
                self.executable,
                "scan",
                normalized_target,
                "-w",
                str(seed_wordlist),
                f"-A=apiroutes-260227:{route_limit}",
                "--force-method",
                "GET",
                "--disable-precheck",
                "--wildcard-detection=false",
                "--max-redirects",
                "0",
                "--delay",
                "100ms",
                "-x",
                "2",
                "-j",
                "1",
                "-t",
                "2s",
                "-q",
                "-o",
                "json",
            ]
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=(
                        self.SEED_SCAN_TIMEOUT_SECONDS
                        if timeout_seconds is None
                        else max(5, min(int(timeout_seconds), 90))
                    ),
                    check=False,
                )
            except FileNotFoundError as exc:
                raise FileNotFoundError(
                    f"Kiterunner executable not found: {self.executable}"
                ) from exc
            except subprocess.TimeoutExpired as exc:
                raise TimeoutError(
                    "Kiterunner seeded API scan timed out "
                    f"(target={normalized_target}, "
                    f"timeout={self.SEED_SCAN_TIMEOUT_SECONDS}s, "
                    f"command={exc.cmd!r})."
                ) from exc

        output_text = "\n".join(part for part in [result.stdout, result.stderr] if part)
        results = self._parse_json_lines(output_text)
        if result.returncode not in (0, 1):
            diagnostic = self._failure_diagnostic(result.stderr, result.stdout)
            raise RuntimeError(
                "Kiterunner seeded API scan failed "
                f"(exit_code={result.returncode}, command={result.args!r})"
                f": {diagnostic}"
            )
        for endpoint in results:
            endpoint["discovery_phase"] = "seeded"
        return {
            "target": normalized_target,
            "seed_count": len(static_paths),
            "exit_code": result.returncode,
            "result_count": len(results),
            "results": results,
            "command": result.args,
        }
