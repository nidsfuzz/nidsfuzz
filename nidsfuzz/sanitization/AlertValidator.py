from collections import deque
from queue import Queue

from logger import logger
from sanitization import test_oracle
from sanitization.AlignedBundle import AlignedBundle


class AlertValidator:

    LAG_SIZE = 5

    def __init__(self,
                 test_bundles: Queue[tuple],
                 nids_bundles: dict[str, deque[tuple]],
                 port_window: deque[int], ):
        if port_window.maxlen is None:
            raise ValueError(f'The maxlen of port window is not defined.')

        self.test_bundles = test_bundles
        self.nids_bundles = nids_bundles
        self.port_window = port_window
        self.memory_span = self.port_window.maxlen

        ################# State Variables ##################
        self.aligned_bundles: deque[AlignedBundle] = deque(maxlen=self.memory_span)

    def _sanitize(self):
        aligned_bundle = self.aligned_bundles.popleft()
        input_rules = aligned_bundle.input_rules
        output_rules = aligned_bundle.output_rules

        logger.debug(f'\tSanitizing test bundle {aligned_bundle}')
        all_passed, _ = test_oracle.run(input_rules, output_rules)

        if all_passed:
            logger.debug(f'\tAll NIDS platforms generated the same alerts for the test case: {input_rules}')
            return None
        else:
            logger.debug(f'\tFound a rule enforcement issue: {input_rules}')
            return aligned_bundle.ensemble

    def _locate(self, port: int) -> AlignedBundle | None:
        for aligned_bundle in self.aligned_bundles:
            if aligned_bundle.port == port:
                return aligned_bundle
        else:
            return None

    def _align(self, test_bundle: tuple):
        aligned_bundle = AlignedBundle(
            test_bundle=test_bundle,
            nids_platforms=self.nids_bundles.keys(),
        )
        seed_rules, client_addr, server_addr, requests, responses = aligned_bundle.test_bundle
        logger.debug(f'\tPushing test bundle: {aligned_bundle.input_rules}, endpoints: {client_addr} <-> {server_addr}')

        for file_path, alert_deque in self.nids_bundles.items():
            logger.debug(f'\tAligning nids platform: {file_path}')
            while True:
                if len(alert_deque) <= 0:
                    logger.debug(f'\tThere is not alerts in {file_path}')
                    break

                rule_id, src_ip, src_port, dst_ip, dst_port = alert_deque[0]
                source_addr = (src_ip, int(src_port))
                destination_addr = (dst_ip, int(dst_port))

                if {client_addr, server_addr} == {source_addr, destination_addr}:
                    logger.debug(f'\tFound a matched alert, aligning it: [{rule_id}, {source_addr}, {destination_addr}]')
                    aligned_bundle.add_alert(nids_platform=file_path, alert=alert_deque.popleft())
                    continue
                else:
                    port = ({source_addr, destination_addr} - {server_addr}).pop()[1]
                    if bundle := self._locate(port=port):
                        logger.debug(f'\tFound a tolerable delayed alert, calibrating it: [{rule_id}, {source_addr}, {destination_addr}]')
                        bundle.add_alert(nids_platform=file_path, alert=alert_deque.popleft())
                        continue
                    elif port not in self.port_window:
                        logger.warning(f'\tFound a severe delayed alert, discarding it: [{rule_id}, {source_addr}, {destination_addr}]')
                        logger.warning(f'\tCurrent port window: {self.port_window}')
                        alert_deque.popleft()
                        continue
                    else:
                        logger.debug(f'\tFound a mismatched port, finishing alignment: {rule_id}, {source_addr} -> {destination_addr}')
                        break
        self.aligned_bundles.append(aligned_bundle)


    def validate(self) -> list[tuple]:
        logger.debug(f'>>> Start validating <<<')

        result = []
        while self.test_bundles.qsize() > self.LAG_SIZE:
            test_bundle = self.test_bundles.get(block=False)
            self._align(test_bundle)

            if len(self.aligned_bundles) >= self.memory_span:
                sanitization_result = self._sanitize()
                if sanitization_result is not None:
                    result.append(sanitization_result)
            else:
                logger.debug(f'\tThere are no aligned bundles. Expected {self.memory_span} but currently {len(self.aligned_bundles)}.')

        logger.debug(f'>>> Stop validating <<<')
        return result

    def finalize(self) -> list[tuple]:
        logger.debug(f'>>> Finalize validating <<<')

        result = []
        while not self.test_bundles.empty():
            test_bundle = self.test_bundles.get(block=False)
            self._align(test_bundle)

            if len(self.aligned_bundles) >= self.memory_span:
                sanitization_result = self._sanitize()
                if sanitization_result is not None:
                    result.append(sanitization_result)

        for _ in range(len(self.aligned_bundles)):
            sanitization_result = self._sanitize()
            if sanitization_result is not None:
                result.append(sanitization_result)

        assert len(self.aligned_bundles) == 0
        logger.info(f'>>> All test packets are consumed by the sanitizer.')

        for file_path, alert_deque in self.nids_bundles.items():
            assert len(alert_deque) == 0
        logger.info(f'>>> All monitored alerts are consumed by the sanitizer.')

        return result




