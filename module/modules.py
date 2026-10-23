import os

from module.authentication_test import AuthenticationTest
from module.endpoint_selection import EndpointSelector


_UNSELECTED = object()


class Modules:
    TEST_MODULE = EndpointSelector.TEST_MODULE

    def __init__(self, endpoint_selector=None, authentication_test=None):
        self.endpoint_selector = endpoint_selector or EndpointSelector()
        self.authentication_test = authentication_test or AuthenticationTest(
            self.endpoint_selector
        )

    def classify_endpoint(self, endpoint):
        return self.endpoint_selector.classify_endpoint(endpoint)

    def select_authentication_candidate(self, discovered_endpoints):
        protected_path = os.environ.get("MICROSCAN_PROTECTED_ENDPOINT", "").strip()
        return self.endpoint_selector.select_authentication_candidate(
            discovered_endpoints,
            override_path=protected_path or None,
        )

    def evaluate_authentication_test(
        self,
        target,
        discovered_endpoints=None,
        selected_candidate=_UNSELECTED,
    ):
        if selected_candidate is _UNSELECTED:
            selected_candidate = self.select_authentication_candidate(
                discovered_endpoints
            )
        return self.authentication_test.evaluate(
            target,
            selected_candidate,
            discovered_endpoints,
        )

    def analyze_endpoints(self, target, results):
        analyzed = []
        authentication_endpoint = None
        for endpoint in results:
            classification = self.endpoint_selector.classify_endpoint(endpoint)
            endpoint.update(
                {
                    "classification": classification["classification"],
                    "classification_reason": classification["reason"],
                    "applicable_tests": classification["applicable_tests"],
                    "test_results": [],
                }
            )
            if (
                self.TEST_MODULE in classification["applicable_tests"]
                and authentication_endpoint is None
            ):
                authentication_endpoint = endpoint
            analyzed.append(endpoint)

        selected_candidate = self.select_authentication_candidate(analyzed)
        if selected_candidate and selected_candidate["endpoint"] is not None:
            authentication_endpoint = selected_candidate["endpoint"]
            authentication_endpoint["applicable_tests"] = list(
                dict.fromkeys(
                    authentication_endpoint["applicable_tests"] + [self.TEST_MODULE]
                )
            )
        elif selected_candidate is not None and analyzed and authentication_endpoint is None:
            authentication_endpoint = analyzed[0]

        if authentication_endpoint is not None:
            authentication_endpoint["test_results"].append(
                self.evaluate_authentication_test(
                    target,
                    analyzed,
                    selected_candidate=selected_candidate,
                )
            )
        return analyzed
