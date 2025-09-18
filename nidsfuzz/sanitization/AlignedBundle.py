

class AlignedBundle:

    def __init__(self, test_bundle: tuple, nids_platforms: set[str]):
        self._test_bundle: tuple = test_bundle
        self._nids_bundles: dict[str, list[tuple]] = {}
        for nids_platform in nids_platforms:
            self._nids_bundles[nids_platform] = []

    @property
    def test_bundle(self) -> tuple:
        seed_rules, client_addr, server_addr, requests, responses = self._test_bundle
        return seed_rules, client_addr, server_addr, requests, responses

    @property
    def nids_bundles(self) -> dict[str, list[tuple]]:
        return self._nids_bundles

    @property
    def port(self) -> int:
        _, client_addr, _, _, _ = self.test_bundle
        return client_addr[1]

    @property
    def input_rules(self) -> list[str]:
        seed_rules, _, _, _, _ = self.test_bundle
        return [rule.id for rule in seed_rules]

    @property
    def output_rules(self) -> list[list[str]]:
        result = []
        for _, alert_list in self._nids_bundles.items():
            result.append(
                [alert[0] for alert in alert_list]
            )
        return result

    def __str__(self):
        return f"AlignedBundle(input={self.input_rules}, output={self.output_rules})"

    def add_alert(self, nids_platform: str, alert: tuple):
        self._nids_bundles[nids_platform].append(alert)

    @property
    def ensemble(self) -> tuple:
        seed_rules, client_addr, server_addr, requests, responses = self._test_bundle
        return seed_rules, client_addr, server_addr, requests, responses, self._nids_bundles


