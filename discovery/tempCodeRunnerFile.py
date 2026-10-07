from discovery.kiterunner import KiteRunner


class Discovery:
    def discover(self, target: str, num: int = 1000):
        scanner = KiteRunner()
        results = scanner.kiterunner_scan(target, num)
        print(len(results))
        return results
        
        
if __name__ == "__main__":
    discovery = Discovery()
    results = discovery.discover("localhost:8085", 1000)
    print(results)