from discovery.kiterunner import KiteRunner


class Discovery:
    def discover(
        self,
        target: str,
        num: int = 10000,
        return_outcome=False,
        timeout_seconds=None,
    ):
        scanner = KiteRunner()
        return scanner.kiterunner_scan(
            target,
            num,
            return_outcome=return_outcome,
            timeout_seconds=timeout_seconds,
        )

    def discover_seeded(
        self,
        target: str,
        seed_paths: list[str],
        num: int = 100,
        timeout_seconds: int | None = None,
    ):
        scanner = KiteRunner()
        return scanner.kiterunner_seed_scan(
            target, seed_paths, num, timeout_seconds=timeout_seconds
        )


if __name__ == "__main__":
    discovery = Discovery()
    results = discovery.discover("localhost:8085", 10000)
    print(results)