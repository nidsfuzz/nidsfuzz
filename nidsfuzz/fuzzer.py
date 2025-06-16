import sys
from pathlib import Path
from queue import Queue

from adaptation import AccumulationAnalyzer
from commons import PortAllocator, save_alert_discrepancies, save_test_packets
from generation import load_mutator
from injection import TunableInitiator
from preprocessing import Rule, RuleSet, load_selector
from sanitization import AlertSanitizer

from logger import logger_manager
logger = logger_manager.setup_logger("fuzzer")


class Fuzzer:

    output_test_packets = "packets.bin"
    output_alert_discrepancies = "discrepancies.txt"

    def __init__(self,
                 initiator_ip: str,
                 responder_ip: str,
                 orch_port: int,
                 data_port: int,
                 our_dir: str):
        self.initiator_ip = initiator_ip
        self.responder_ip = responder_ip
        self.orch_port = orch_port
        self.data_port = data_port

        self.out_anchor = Path(our_dir)
        self.out_test_packets_file = self.out_anchor / self.output_test_packets
        self.out_alert_discrepancies_file = self.out_anchor / self.output_alert_discrepancies

        self._is_running = True

        self.tunable_initiator = TunableInitiator(
            host=self.responder_ip,
            orch_port=self.orch_port,
            data_port=self.data_port
        )

        self.rule_pool = None  # RuleSet
        self.rule_batch = None  # list[Rule]
        self.rule_selector = None  # Generator[list[Rule], None, None]

        self.rule_mutator = None  # GenericStrategy

        self.port_allocator = None  # PortAllocator

        self.alert_sanitizer = None  # AlertSanitizer

        self.test_case_queue = Queue()
        self.sanitized_case_queue = Queue()

        self.accumulation_analyzer = None  # AccumulationAnalyzer

    def setup_rule_selector(self,
                            rule_files: list[str],
                            algorithm: str,
                            batch_size: int = 1,
                            repeatable: bool = False
                            ):
        self.rule_pool = RuleSet.from_files(file_paths=rule_files)
        self.rule_selector = load_selector(
            algorithm=algorithm,
            rule_pool=self.rule_pool,
            batch_size=batch_size,
            repeatable=repeatable
        )
        return self

    def setup_rule_mutator(self,
                           strategy: str):
        self.rule_mutator = load_mutator(strategy=strategy)
        return self

    def setup_alert_sanitizer(self,
                              monitored_files: list[str],
                              timeout = 0.5,
                              port_window_size: int = 25
                              ):
        self.port_allocator = PortAllocator(port_window_size=port_window_size)
        self.alert_sanitizer = AlertSanitizer(
            test_queue=self.test_case_queue,
            sanitized_test_queue=self.sanitized_case_queue,
            alert_files=monitored_files,
            timeout=timeout,
            port_window_size=port_window_size
        )
        return self

    def setup_accumulation_analyzer(self, threshold: int = 1):
        self.accumulation_analyzer = AccumulationAnalyzer(threshold=threshold)
        return self


    def start(self):
        while self._is_running:
            try:
                # Select rules for testing in this fuzzing iteration
                while True:
                    self.rule_batch: list[Rule] = next(self.rule_selector)
                    selected_rules = ', '.join([rule.id for rule in self.rule_batch])
                    # Check whether the selected rules deserve to be tested
                    if self.accumulation_analyzer.validate_rules_for_testing(rules=selected_rules):
                        break
                logger.debug(f"selected rule: {selected_rules}")
            except StopIteration:
                logger.success(f'no more rules needed to be tested')
                self.stop()
                sys.exit(0)

            # Generate test packets by mutating the selected rules
            mutants = self.rule_mutator.mutate(self.rule_batch)

            # Injection phase
            for request, response in mutants:
                # Explicitly specify the port used for the tunable initiator
                data_port, orch_port = self.port_allocator.allocate_ports()
                logger.debug(f'Allocated ports: [{data_port}, {orch_port}]')

                # Organize the observed information for subsequent sanitization
                initiator_data_sock = (self.initiator_ip, data_port)
                responder_data_sock = (self.responder_ip, self.data_port)
                self.test_case_queue.put((selected_rules, initiator_data_sock, responder_data_sock, request, response))

                # Inject the test packets into the NIDSs under test
                initiator_orch_sock = (self.initiator_ip, orch_port)
                self.tunable_initiator.fuzz(
                    request=request,
                    response=response,
                    orch_sock=initiator_orch_sock,
                    data_sock=initiator_data_sock
                )

            # Sanitization phase
            self.alert_sanitizer.sanitize(port_window=self.port_allocator.port_window)

            while not self.sanitized_case_queue.empty():
                rule_id, initiator, responder, request, response, aligned_alerts = self.sanitized_case_queue.get()
                logger.success(f'selected rule(s): {rule_id}')
                logger.success(f'traffic info: {initiator} -> {responder}')
                logger.success(f'alert discrepancy: {aligned_alerts}')
                # Save alert discrepancies to the file
                save_alert_discrepancies(
                    file_path=f'{self.out_alert_discrepancies_file}',
                    selected_rules=rule_id,
                    aligned_alerts=aligned_alerts
                )
                # Save test packets to the file
                save_test_packets(
                    file_path=f'{self.out_test_packets_file}',
                    request=request,
                    response=response
                )

                # Adaptation phase
                self.accumulation_analyzer.update_accumulation(rules=rule_id)


    def stop(self):
        self._is_running = False
        if self.tunable_initiator is not None:
            self.tunable_initiator.stop()

        if self.alert_sanitizer is not None:
            self.alert_sanitizer.exit()





