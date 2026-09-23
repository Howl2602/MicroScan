from discovery.kiterunner import KiteRunner


class Discovery:
    def discover(self, target: str, num: int = 1000):
        scanner = KiteRunner()
        results = scanner.kiterunner_scan(target, num)
        print(len(results))
        return results
        
        
