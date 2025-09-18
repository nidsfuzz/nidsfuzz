import pathlib
import struct
import sys
import threading
import time
from collections import deque
from itertools import groupby
from queue import Queue
from typing import Generator

from generation import PassThroughMutator, BlendingMutator, RepetitionMutator, ObfuscationMutator
from logger import logger
from commons import PortAllocator, AccumulationAnalyzer
from injection import TunableInitiator
from rule import Proto, Rule, RuleSet
from sanitization import AlertMonitor, AlertValidator
from selection import SequentialSelector, CombinationSelector, RandomSelector


class Fuzzer:

    def __init__(self,
                 initiator_addr: str,
                 responder_addr: str,
                 tuning_port: int,
                 tuned_port: int,
                 output_dir: str,
                 proto: str = None, ):
        if proto is not None and proto.lower() not in Proto.all():
            raise ValueError(f'Unsupported protocol: {proto}')

        self.initiator_addr = initiator_addr
        self.responder_addr = responder_addr
        self.tuning_port = tuning_port
        self.tuned_port = tuned_port
        self.protocol = proto
        self.output_dir = output_dir

        self.port_allocator = PortAllocator()
        self.tunable_initiator = TunableInitiator(
            host=responder_addr,
            tuning_port=tuning_port,
            tuned_port=tuned_port,
        )

        ##############################
        self.rule_pool = None
        self.rule_selector = None
        self.rule_mutator = None

        self.test_bundle = Queue()

        self.monitored_alerts = None
        self.alert_monitor = None
        self.alert_validator = None

        self.accumulation_analyzer = None

        self._running = False
        self._thread = None

        ##############################
        self._selected_rules: list[Rule] = None
        self._selected_proto: str = None
        self._requests: list[bytes] = None
        self._responses: list[bytes] = None
        self._flawed_rules: list[Rule] = None

        logger.success(f'Initialized Fuzzer with protocol: {self.protocol}')

    def setup_selection(self,
                        rule_files: list[str],
                        algorithm: str,
                        batch_size: int = 1,
                        batch_num: int = 10000, ):
        self.rule_pool = RuleSet.from_files(file_paths=rule_files)
        logger.success(f'Loaded rule files: {rule_files}')
        logger.success(f'{str(self.rule_pool)}')

        match algorithm.lower():
            case 'sequential':
                self.rule_selector = SequentialSelector(
                    ruleset=self.rule_pool,
                    batch_size=batch_size,
                    batch_num=batch_num,
                    proto=self.protocol,
                )
            case 'combination':
                self.rule_selector = CombinationSelector(
                    ruleset=self.rule_pool,
                    batch_size=batch_size,
                    batch_num=batch_num,
                    proto=self.protocol,
                )
            case 'random':
                self.rule_selector = RandomSelector(
                    ruleset=self.rule_pool,
                    batch_size=batch_size,
                    batch_num=batch_num,
                    proto=self.protocol,
                )
            case _:
                raise ValueError(f"Unknown selection algorithm: '{algorithm}'")

        logger.success(f'Setting up selection strategy: {algorithm}.')
        return self

    def setup_generation(self,
                         algorithm: str,
                         mode: str = 'block-wise', ):
        match algorithm.lower():
            case 'pass-through':
                self.rule_mutator = PassThroughMutator(ruleset=self.rule_pool)
            case 'blending':
                self.rule_mutator = BlendingMutator(ruleset=self.rule_pool)
            case 'repetition':
                if mode != 'block-wise' and mode != 'element-wise':
                    raise ValueError(f'Invalid repetition mode: {mode}')
                self.rule_mutator = RepetitionMutator(ruleset=self.rule_pool, mode=mode)
            case 'obfuscation':
                self.rule_mutator = ObfuscationMutator(ruleset=self.rule_pool)
            case _:
                raise ValueError(f"Unknown generation algorithm: '{algorithm}'")
        logger.success(f'Setting up generation strategy: {algorithm}.')
        return self

    def setup_sanitization(self,
                           alert_files: list[str], ):
        self.monitored_alerts = {alert_file: deque() for alert_file in alert_files}
        self.alert_monitor = AlertMonitor(monitored_alerts=self.monitored_alerts)
        self.alert_validator = AlertValidator(
            nids_bundles=self.monitored_alerts,
            test_bundles=self.test_bundle,
            port_window=self.port_allocator.memory, )
        logger.success(f'Setting up alert sanitizer.')
        return self

    def setup_adaptation(self, threshold: int = 1):
        self.accumulation_analyzer = AccumulationAnalyzer(threshold=threshold)
        logger.success(f'Setting up accumulation analyzer.')
        return self

    def fuzz_loop(self):
        self._initialize()
        while self._running:
            self._pre_fuzzing_run()
            self._selection()
            self._generation()
            self._injection()
            self._sanitization()
            self._post_fuzzing_run()
        self._finalize()

    def start(self):
        self._running = True
        # Start the monitoring threads
        self.alert_monitor.start()
        self.alert_monitor.resume()
        # Start the fuzzing thread
        self._thread = threading.Thread(target=self.fuzz_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self.tunable_initiator.is_connected:
            self.tunable_initiator.teardown()
        self.alert_monitor.stop()

    def join(self):
        if self._thread:
            self._thread.join()

    def _initialize(self):
        pass

    def _pre_fuzzing_run(self):
        self._selected_rules = None
        self._selected_proto = None
        self._flawed_rules = None

    def _selection(self):
        try:
            self._selected_proto, self._selected_rules = next(self.rule_selector)
            logger.debug(f'Selection phase finished: {self._selected_proto} >>> {[rule.id for rule in self._selected_rules]}')
        except StopIteration:
            logger.info(f'There is no rules need to be validated.')
            self.stop()

    def _generation(self):
        if self._selected_proto is None:
            raise RuntimeError(f'The selected rules and protocol are None, please exec selection before generating test packets.')

        self._requests: list[bytes] = []
        self._responses: list[bytes] = []
        for request, response in self.rule_mutator.generate(*self._selected_rules, proto=self._selected_proto):
            self._requests.append(request)
            self._responses.append(response)

        logger.debug(f'Generation phase finished. Size of bilateral packets: [requests: {len(self._requests)}, responses: {len(self._responses)}]')

    def _injection(self):
        if len(self._requests) == 0 and len(self._responses) == 0:
            logger.info(f'No packet generated. Injection phase finished.')
            return

        tuned_port = self.port_allocator.allocate(memorize=True)
        tuning_port = self.port_allocator.allocate(memorize=False)

        self.tunable_initiator.connect(
            (self.initiator_addr, tuning_port),
            (self.initiator_addr, tuned_port))
        for request, response in zip(self._requests, self._responses):
            self.tunable_initiator.inject(request=request, response=response)
        self.tunable_initiator.teardown()

        self.test_bundle.put((
            self._selected_rules,
            (self.initiator_addr, tuned_port),
            (self.responder_addr, self.tuned_port),
            self._requests,
            self._responses,
        ))

        logger.debug(f'Injection phase finished.')

    def _sanitization(self):
        if len(self._requests) == 0 and len(self._responses) == 0:
            logger.info(f'No packet generated. Sanitization phase finished.')
            return

        self._flawed_rules = []
        if self.test_bundle.qsize() >= 50:
            self.alert_monitor.pause()
            while self.test_bundle.qsize() > 5:
                for selected_rules, client_addr, server_addr, requests, responses, platform_alerts in self.alert_validator.validate():
                    flawed_rules: list[Rule] = self.accumulation_analyzer.update(*selected_rules)
                    # self._flawed_rules = [self.rule_pool.find_rule(r) for r in flawed_rules]
                    if None in flawed_rules:
                        raise RuntimeError(f'Flawed rule is invalid: {flawed_rules}')
                    self._flawed_rules.extend(flawed_rules)
                    self.save(self.output_dir, selected_rules, requests, responses, platform_alerts)
            self.alert_monitor.resume()

        logger.debug(f'Sanitization phase finished: {[rule.id for rule in self._flawed_rules]}')

    def _post_fuzzing_run(self):
        if self._flawed_rules is not None and len(self._flawed_rules) > 0:
            self.rule_selector.filter(*self._flawed_rules)

        # Add some interval to avoid overwhelming NIDS platforms.
        time.sleep(0.1)

        if self.rule_selector.count >= self.rule_selector.batch_num:
            logger.info(f'There is no rules need to be validated.')
            self.stop()

    def _finalize(self):
        for selected_rules, client_addr, server_addr, requests, responses, platform_alerts in self.alert_validator.finalize():
            flawed_rules: list[Rule] = self.accumulation_analyzer.update(*selected_rules)
            if None in flawed_rules:
                raise RuntimeError(f'Flawed rule is invalid: {flawed_rules}')
            self.save(self.output_dir, selected_rules, requests, responses, platform_alerts)

    @staticmethod
    def save(file_anchor: str,
             rule_id: list[Rule],
             requests: list[bytes],
             responses: list[bytes],
             platform_alerts: dict[str, list[tuple[str, str, str, str, str]]]):
        # Write the human-readable alert information
        file_discrepancies = pathlib.Path(file_anchor) / 'discrepancies.txt'
        with open(file_discrepancies, 'a', encoding='utf-8') as f:
            f.write(f"seed rules: {', '.join([rule.id for rule in rule_id])}" + '\n')
            for platform, alert_list in platform_alerts.items():
                fired_rules = ', '.join([e[0] for e in alert_list])  # Only record the ID of the fired rules
                f.write(f'{platform}: {fired_rules}' + '\n')
            f.write('\n')
        # Write the test packets corresponding to the alert event
        file_packets = pathlib.Path(file_anchor) / 'packets.bin'
        with open(file_packets, 'ab') as f:
            for request, response in zip(requests, responses):
                f.write(struct.pack('!I', len(request)))
                f.write(request)
                f.write(struct.pack('!I', len(response)))
                f.write(response)
            f.write(b'\xff\xff\xff\xff')

    @staticmethod
    def load_discrepancies(file_anchor: str) -> Generator[tuple[list[str], dict[str, list[str]]], None, None]:
        file_discrepancies = pathlib.Path(file_anchor) / 'discrepancies.txt'
        seperator = ""

        with open(file_discrepancies, 'r') as f:
            for is_seperator, group in groupby(f, key=lambda line: line.strip() == seperator):
                if is_seperator:
                    continue

                first_line = next(group).strip()
                _, seed_rules = first_line.split(": ", 1)
                seed_rules = seed_rules.split(", ")

                platform_alerts = {}
                for line in group:
                    platform, alerts = line.strip().split(":", 1)
                    platform_alerts[platform.strip()] = alerts.strip().split(", ") if alerts.strip() != '' else []

                yield seed_rules, platform_alerts

    @staticmethod
    def load_packets(file_anchor: str) -> Generator[tuple[list[bytes], list[bytes]], None, None]:
        file_packets = pathlib.Path(file_anchor) / 'packets.bin'
        seperator = b'\xff\xff\xff\xff'

        with open(file_packets, 'rb') as f:
            while f.peek(1):
                requests, responses = [], []
                while (length_data := f.read(4)) != seperator:
                    if not length_data:
                        break

                    request_len = struct.unpack('!I', length_data)[0]
                    requests.append(f.read(request_len))

                    response_len = struct.unpack('!I', f.read(4))[0]
                    responses.append(f.read(response_len))

                if requests or responses:
                    yield requests, responses