from pathlib import Path

from rule.Rule import Rule
from rule.options import Flowbits


class RuleSet:
    """
    Methods:
    --------
    serialize(self):
        Converts the RuleSet into a readable and easily storable string format.

    deserialize(cls, data: str) -> 'RuleSet':
        Deserializes a serialized string into a RuleSet object.

    from_file(cls, file_path: str) -> 'RuleSet':
        Creates a RuleSet object using all the rules from a rules file.

    from_rules(cls, rules: list[Rule]) -> 'RuleSet':
        Creates a RuleSet object from rules.


    Example Usage:
    --------
    Creates RuleSet objects from rules files:

    >>> ftp_rules_file = 'ftp.rules'
    >>> http_rules_file = 'http.rules'
    >>> ftp_ruleset = RuleSet.from_file(ftp_rules_file)
    >>> http_ruleset = RuleSet.from_file(http_rules_file)

    Adds two RuleSet objects together and then get the attributes of the added objects:

    >>> ruleset = ftp_ruleset + http_ruleset
    >>> activated_rules = ruleset.activated_rules
    >>> commented_rules = ruleset.commented_rules
    >>> flowbits = ruleset.flowbits

    Groups Rules in RuleSet based on the provided criteria:
    
    >>> tcp_rules = ruleset.group(protocol='tcp')
    """

    def __init__(self):
        self._activated_rules: list[Rule] = []
        self._commented_rules: list[Rule] = []
        self._unresolved_rules: list[str] = []

        self._set_flowbits: dict[str, list[Rule]] = {}
        self._check_flowbits: dict[str, list[Rule]] = {}

    @property
    def rules(self) -> list[Rule]:
        return [*self._activated_rules, *self._commented_rules]

    @property
    def activated_rules(self) -> list[Rule]:
        return self._activated_rules

    @property
    def commented_rules(self) -> list[Rule]:
        return self._commented_rules

    @property
    def flowbits(self) -> set[str]:
        return set(self._set_flowbits.keys()) | set(self._check_flowbits.keys())

    def __str__(self) -> str:
        return f"Activated Rules: {len(self._activated_rules)}, Commented Rules: {len(self._commented_rules)}, Unresolved Rules: {len(self._unresolved_rules)}"

    def __repr__(self) -> str:
        return str(self)

    def __add__(self, other: 'RuleSet') -> 'RuleSet':
        if isinstance(other, RuleSet):
            res = RuleSet()
            res._activated_rules = self._activated_rules + other._activated_rules
            res._commented_rules = self._commented_rules + other._commented_rules
            res._resolve_flowbits()
            return res
        else:
            return NotImplemented

    def group(self, protocol: str = None, port: str = None, service: str = None) -> 'RuleSet':
        """
        When Snort starts or reloads configuration, rules are grouped by protocol, port and service.
        For example, all TCP rules using the HTTP_PORTS variable will go in one group and
        all service HTTP rules will go in another group. These rule groups are compiled
        into multi-pattern search engines (MPSE) which are designed to search for all
        patterns with just a single pass through a given packet or buffer.
        """
        rule_group = RuleSet()

        def _group(criteria: dict[str, str]):
            for rule in self._activated_rules:
                for k, v in criteria.items():
                    # case-insensitive comparison
                    if v.casefold() not in getattr(rule, k).casefold():
                        break
                else:
                    rule_group._activated_rules.append(rule)
            for rule in self._commented_rules:
                for k, v in criteria.items():
                    # case-insensitive comparison
                    if v.casefold() not in getattr(rule, k).casefold():
                        break
                else:
                    rule_group._commented_rules.append(rule)

        criteria = {}
        if protocol is not None:
            criteria['protocol'] = protocol
        if port is not None:
            criteria['port'] = port
        if service is not None:
            criteria['service'] = service
        _group(criteria)
        rule_group._resolve_flowbits()
        return rule_group

    @classmethod
    def from_file(cls, file_path: str) -> 'RuleSet':
        rule_set = cls()

        with Path(file_path).open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if Rule.is_valid(line):
                    rule = Rule.from_string(line)
                    if rule is None:
                        # print(f"Not Implemented rule format: {line}")
                        rule_set._unresolved_rules.append(line)
                    elif rule.activated:
                        rule_set._activated_rules.append(rule)
                    else:
                        rule_set._commented_rules.append(rule)
        rule_set._resolve_flowbits()
        return rule_set

    @classmethod
    def from_files(cls, file_paths: list[str], proto: str = None):
        # load rule files
        rule_pool = None
        for file_path in file_paths:
            ruleset = RuleSet.from_file(file_path)
            if rule_pool is None:
                rule_pool = ruleset
            else:
                rule_pool = rule_pool + ruleset

        # group rules
        if proto is not None:
            rule_pool = rule_pool.group(service=proto)

        return rule_pool

    @classmethod
    def from_rules(cls, rules: list[Rule]) -> 'RuleSet':
        rule_set = cls()
        for rule in rules:
            if rule.activated:
                rule_set._activated_rules.append(rule)
            else:
                rule_set._commented_rules.append(rule)
        rule_set._resolve_flowbits()
        return rule_set


    def _resolve_flowbits(self):
        for rule in self.rules:
            if rule.get('flowbits') is None:
                continue
            for flowbits in rule.get('flowbits'):
                flowbits = Flowbits.from_string(flowbits)
                for set_flowbits in flowbits.setters:
                    self._set_flowbits.setdefault(set_flowbits, []).append(rule)
                for check_flowbits in flowbits.checkers:
                    self._check_flowbits.setdefault(check_flowbits, []).append(rule)

    def find_rule(self, rule_id: str) -> Rule | None:
        return next((rule for rule in self.rules if rule.id == rule_id), None)

if __name__ == '__main__':
    rule_file = Path(__file__).parent.parent.parent / 'resources' / 'rules' / 'snort3-community.rules'
    ruleset = RuleSet.from_file(f'{rule_file}')

    print(f"Info: \n\t{ruleset}")
    print(f"Flowbits: \n\t{ruleset.flowbits}")

    tcp_ruleset = ruleset.group(protocol='TCP', port=None, service=None)
    print(f"TCP Rules Info: \n\t{tcp_ruleset}")
    print(f"Flowbits: \n\t{tcp_ruleset.flowbits}")

    rule_id = "1:208:13"
    print(f"Finding rule ({rule_id}): \n\t{ruleset.find_rule(rule_id)}")

