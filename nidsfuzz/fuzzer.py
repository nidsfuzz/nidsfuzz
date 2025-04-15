import os
import random
import sys
from queue import Queue

import psutil

import logger
from alert_sanitizer import AlertSanitizer
from commons import utils
from rule_handler import RuleSet, Rule
from rule_mutator.rule_mutator import RuleMutator
from rule_selector import RuleSelector
from traffic_injector.tunable_initiator import TunableInitiator


def load_rules(rule_files, group: str = None) -> RuleSet:
    # load rule files
    rule_pool = None
    for rule_file in rule_files:
        logger.debug(f"loading rule file: {rule_file}")
        ruleset = RuleSet.from_file(rule_file)
        logger.debug(f"{str(ruleset)}")
        if rule_pool is None:
            rule_pool = ruleset
        else:
            rule_pool = rule_pool + ruleset

    # group rules
    if group is not None:
        logger.debug(f"grouping rules based on criteria: protocol={group}")
        rule_pool = rule_pool.group(service=group)
        logger.debug(f"grouped rules: {str(rule_pool)}")

    return rule_pool


##############################################################################
##############################################################################

class Fuzzer:
    TRAFFIC_FILENAME = 'traffic.bin'
    STATISTICS_FILENAME = 'statistics.txt'

    def __init__(self,
                 local_ip: str,
                 remote_ip: str,
                 echo_port: int,
                 data_port: int,
                 out_dir: str,
                 ):
        self.local_ip = local_ip
        self.remote_ip = remote_ip
        self.echo_port = echo_port
        self.data_port = data_port
        self.test_traffic_file = os.path.join(out_dir, self.TRAFFIC_FILENAME)
        self.test_statistics_file = os.path.join(out_dir, self.STATISTICS_FILENAME)

        self._running = True

        self.tunable_initiator = TunableInitiator(self.remote_ip, self.echo_port, self.data_port)

        # The following variables are initialised in the apply_strategy() function
        self.select_strategy = None
        self.mutate_strategy = None
        self.rule_pool = None
        self.rule_batch = None
        self.rule_selector = None
        self.rule_mutator = None

        # The following variables are initialised in the apply_sanitizer() function
        self.port_selector = None
        self.alert_sanitizer = None
        self.test_queue = Queue()
        self.sanitized_test_queue = Queue()

    def apply_strategy(self,
                       select_strategy: str,
                       mutate_strategy: str,
                       rule_files: list[str],
                       batch_size: int = 1,
                       repeatable: bool = False,
                       only_activated: bool = False):
        if mutate_strategy not in RuleMutator.STRATEGY:
            raise ValueError("Invalid mutate strategy")

        self.select_strategy = select_strategy
        self.mutate_strategy = mutate_strategy

        self.rule_pool = load_rules(rule_files)
        self.rule_selector = RuleSelector(
            select_strategy=select_strategy,
            batch_size=batch_size,
            repeatable=repeatable,
            only_activated=only_activated,
        ).select(self.rule_pool)
        self.rule_mutator = RuleMutator(mutate_strategy=mutate_strategy)
        logger.debug(f'applied select strategy: {self.select_strategy}, mutate strategy: {self.mutate_strategy}')

    def apply_sanitizer(self,
                        alert_files: list[str],
                        timeout=0.5,
                        n_tests: int = 25
                        ):
        self.port_selector = PortSelector(max_history=n_tests)
        self.alert_sanitizer = AlertSanitizer(
            test_queue=self.test_queue,
            sanitized_test_queue=self.sanitized_test_queue,
            alert_files=alert_files,
            timeout=timeout,
            n_tests=n_tests
        )
        logger.debug(f'applied sanitizer: {self.alert_sanitizer}')

    def start(self):
        while self._running:
            # load rule_batch
            try:
                self.rule_batch: list[Rule] = next(self.rule_selector)
                logger.debug(f"selected rule: {[rule.id for rule in self.rule_batch]}")
            except StopIteration:
                logger.debug(f'no more rules needed to be tested')
                self.stop()
                sys.exit(0)

            # do mutation
            mutants = self.rule_mutator.mutate(self.rule_batch)

            # traffic injection
            for request, response in mutants:
                # Specify the local addr explicitly
                local_echo_port, local_data_port = self.port_selector.select_ports()
                echo_sock = (self.local_ip, local_echo_port)
                data_sock = (self.local_ip, local_data_port)
                logger.debug(f"local echo port: {local_echo_port}    local data port: {local_data_port}")
                self.test_queue.put(
                    (
                        ', '.join([rule.id for rule in self.rule_batch]),
                        data_sock,
                        (self.remote_ip, self.data_port),
                        request,
                        response,
                    )
                )
                self.tunable_initiator.fuzz(request=request, response=response, echo_sock=echo_sock, data_sock=data_sock)

            # alert sanitization
            self.alert_sanitizer.validate(port_window=self.port_selector.port_window)

            while not self.sanitized_test_queue.empty():
                rule_id, initiator, responder, request, response, aligned_alerts = self.sanitized_test_queue.get()
                logger.debug(f'sanitized {rule_id}, endpoints: {initiator} {responder}')
                logger.debug(f'sanitized {aligned_alerts}')
                self.write_statistics(self.test_statistics_file, rule_id, aligned_alerts)
                utils.write_traffic(self.test_traffic_file, request, response)

    def stop(self):
        self._running = False
        if self.tunable_initiator is not None:
            self.tunable_initiator.stop()

        if self.alert_sanitizer is not None:
            self.alert_sanitizer.exit()

    @staticmethod
    def write_statistics(file_path, rule_id, aligned_alerts):
        with open(file_path, 'a', encoding='utf-8') as f:
            f.write(rule_id + '\n')
            for alert_file, alert_list in aligned_alerts.items():
                triggered_alerts = ', '.join([e[0] for e in alert_list])
                f.write(alert_file + ': ' + triggered_alerts + '\n')
            f.write('\n')

    @staticmethod
    def read_statistics(file_path: str):
        with open(file_path, 'r') as f:
            data_unit = []
            for line in f:
                line = line.strip()
                if line == "":
                    yield data_unit
                    data_unit.clear()
                else:
                    data_unit.append(line)


class PortSelector:

    def __init__(self,
                 start: int = 1024,
                 end: int = 65535,
                 max_history: int = 25):
        self.start = start
        self.end = end
        self.max_history = max_history

        self.used_ports = list()

    @property
    def port_window(self) -> list[int]:
        return self.used_ports

    def select_ports(self) -> tuple[int, int]:
        occupied_ports = {conn.laddr.port for conn in psutil.net_connections() if conn.laddr}
        while True:
            echo_port, data_port = random.sample(range(self.start, self.end), 2)
            if data_port not in occupied_ports and echo_port not in occupied_ports:
                self.used_ports.append(data_port)
                if len(self.used_ports) > self.max_history:
                    del self.used_ports[0]
                return echo_port, data_port
            else:
                logger.debug(f'ports: [{data_port}, {echo_port}] are already in use, trying again...')



