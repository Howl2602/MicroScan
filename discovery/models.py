from discovery.kiterunner import KiteRunner


class Discovery:
    def discover(self, target: str, num: int = 10000):
        scanner = KiteRunner()
        results = scanner.kiterunner_scan(target, num)
        return results


if __name__ == "__main__":
    discovery = Discovery()
    results = discovery.discover("localhost:8085", 10000)
    print(results)