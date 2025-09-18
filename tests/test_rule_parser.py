import itertools
import re

from collections import defaultdict
from pathlib import Path
from unittest import TestCase

from rule import RuleSet


class TestRuleParser(TestCase):

    def setUp(self):
        rules_dir = Path(__file__).parent.parent / "resources" / 'rules'
        self.http_rules = {
            'snort3': rules_dir / "snort3-browser-chrome.rules",
            'snort2': rules_dir / "snort2-browser-chrome.rules",
            'suricata': rules_dir / "snort2-browser-chrome.rules",
        }
        self.sip_rules = {
            'snort3': rules_dir / "snort3-protocol-voip.rules",
            'snort2': rules_dir / "snort2-protocol-voip.rules",
            'suricata': rules_dir / "snort2-protocol-voip.rules",
        }
        self.ftp_rules = {
            'snort3': rules_dir / "snort3-protocol-ftp.rules",
            'snort2': rules_dir / "snort2-protocol-ftp.rules",
            'suricata': rules_dir / "snort2-protocol-ftp.rules",
        }
        self.dns_rules = {
            'snort3': rules_dir / "snort3-protocol-dns.rules",
            'snort2': rules_dir / "snort2-protocol-dns.rules",
            'suricata': rules_dir / "snort2-protocol-dns.rules",
        }
        self.community_rules = {
            'snort3': rules_dir / "snort3-community.rules",
            'snort2': rules_dir / "snort2-community.rules",
            'suricata': rules_dir / "snort2-community.rules",
        }

    @staticmethod
    def extract_rule_id(rule_file: str) -> list[str]:
        rule_id_list: list[str] = []

        sid_pattern = re.compile(r"sid:(\d+);")
        rev_pattern = re.compile(r"rev:(\d+);")
        gid_pattern = re.compile(r"gid:(\d+);")

        with open(rule_file) as f:
            for line in f:
                sid_match = sid_pattern.search(line)
                if not sid_match:
                    continue
                sid_val = sid_match.group(1)

                gid_match = gid_pattern.search(line)
                gid_val = gid_match.group(1) if gid_match else '1'

                rev_match = rev_pattern.search(line)
                rev_val = rev_match.group(1) if rev_match else '1'

                rule_id_list.append(f'{gid_val}-{sid_val}-{rev_val}')

        return rule_id_list

    @staticmethod
    def activate_all_rules(rule_file: str) -> int:
        num_of_activated_rules = 0

        import tempfile, os, shutil
        temp_fd, temp_path = tempfile.mkstemp()

        try:
            with open(rule_file, 'r', encoding='utf-8') as source_file, os.fdopen(temp_fd, 'w',
                                                                                 encoding='utf-8') as temp_file:
                for line in source_file:
                    if "sid:" in line and line.startswith("# "):
                        modified_line = line[2:]
                        num_of_activated_rules += 1
                    else:
                        modified_line = line
                    temp_file.write(modified_line)
            shutil.move(temp_path, rule_file)
            return num_of_activated_rules
        except Exception as e:
            print(f"An error happened: {e}")
            os.remove(temp_path)
            return 0

    def test_comparing_rulesets(self):
        target_rules = self.dns_rules

        snort2_rule_id = set(self.extract_rule_id(str(target_rules['snort2'])))
        print(f'The number of rules in snort2 ruleset: {len(snort2_rule_id)}')

        snort3_rule_id = set(self.extract_rule_id(str(target_rules['snort3'])))
        print(f'The number of rules in snort3 ruleset: {len(snort3_rule_id)}')

        common_rule_id = snort2_rule_id & snort3_rule_id
        print(f'The number of rules that are present in both rule sets is {len(common_rule_id)}.')
        print(f'{list(itertools.islice(common_rule_id, 10))}')

        snort2_exclusive_rule_id = snort2_rule_id - snort3_rule_id
        print(f'The number of rules that appear only in snort2 ruleset is {len(snort2_exclusive_rule_id)}.')
        print(f'{list(itertools.islice(snort2_exclusive_rule_id, 100))}')

        snort3_exclusive_rule_id = snort3_rule_id - snort2_rule_id
        print(f'The number of rules that appear only in snort3 ruleset is {len(snort3_exclusive_rule_id)}.')
        print(f'{list(itertools.islice(snort3_exclusive_rule_id, 100))}')

    def test_activating_rules(self):
        target_rules = self.community_rules

        line_changed = self.activate_all_rules(str(target_rules['snort2']))
        print(f'The number of changed rules in snort2 ruleset: {line_changed}')

        line_changed = self.activate_all_rules(str(target_rules['snort3']))
        print(f'The number of changed rules in snort3 ruleset: {line_changed}')

    def test_displaying_options(self):
        statistics = defaultdict(int)

        target_ruleset = RuleSet.from_file(str(self.sip_rules['snort3'])).group(service='sip')
        print(target_ruleset)

        for rule in target_ruleset.activated_rules:
            for option in rule._rule_body["options"]:
                statistics[option["name"]] += 1

        for option, count in statistics.items():
            print(f"{option}: {count}")

    def test_resolving_flowbits(self):
        target_ruleset = RuleSet.from_file(str(self.community_rules['snort3'])).group(service='http')

        print(target_ruleset)
        print(target_ruleset.flowbits)

    def test_computing_rule_distribution(self):
        protos = ['http', 'sip', 'dns', 'sip']
        rule_files = [
            self.community_rules['snort3'],
        ]

        total_ruleset = RuleSet.from_files(rule_files)
        total_num = len(total_ruleset.rules)

        for proto in protos:
            proto_ruleset = total_ruleset.group(service=proto)
            proto_num = len(proto_ruleset.rules)
            print(f'The proportion of {proto} rules is: {proto_num} / {total_num} = {proto_num / total_num:.4f}')