from unittest import TestCase

from rule_mutator.rule_mutator import RuleMutator
from rule_handler import Rule


class TestRuleMutator(TestCase):

    def test_rule_combine_strategy(self):
        rule_str = (
            r'alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any ( '
            r'msg:"BROWSER-FIREFOX Mozilla products frame comment objects manipulation memory corruption attempt"; '
            r'flow:to_client,established; file_data; '
            r'content: "hello"; '  # added
            r'content: "world!", distance 1, within 7;'  # added
            r'content:"bb.appendChild|28|fr.childNodes[4]|29 3B|",fast_pattern,nocase, distance 7; '  # add distance 7
            r'metadata:policy max-detect-ips drop; service:http; '
            r'reference:bugtraq,21668; reference:cve,2006-6504; '
            r'classtype:attempted-user; sid:15999; rev:9; )'
        )

        rule = Rule.from_string(rule_str)

        rule_mutator = RuleMutator(mutate_strategy='combine')

        for request, response in rule_mutator.mutate([rule, rule]):
            print("request:", request)
            print("response:", response)

    def test_rule_repeat_strategy(self):
        rule_str = (
            r'alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any ( '
            r'msg:"BROWSER-FIREFOX Mozilla products frame comment objects manipulation memory corruption attempt"; '
            r'flow:to_client,established; file_data; '
            r'content: "hello"; '  # added
            r'content: "world!", distance 1, within 7;'  # added
            r'content:"bb.appendChild|28|fr.childNodes[4]|29 3B|",fast_pattern,nocase, distance 7; '  # add distance 7
            r'metadata:policy max-detect-ips drop; service:http; '
            r'reference:bugtraq,21668; reference:cve,2006-6504; '
            r'classtype:attempted-user; sid:15999; rev:9; )'
        )

        rule = Rule.from_string(rule_str)

        rule_mutator = RuleMutator(mutate_strategy='repeat')

        for _request, _response in rule_mutator.mutate([rule]):
            print(_request.decode('latin-1'))
            print(f'---------------------------------------------\n---------------------------------------------\n')

            print(_response.decode('latin-1'))
            print(f'---------------------------------------------\n---------------------------------------------\n')

    def test_rule_obfuscate_strategy(self):
        rule_str = (
            r'alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any ( '
            r'msg:"BROWSER-FIREFOX Mozilla products frame comment objects manipulation memory corruption attempt"; '
            r'flow:to_client,established; file_data; '
            r'content:"/msadc/msadc.dll",fast_pattern,nocase; '
            r'pcre:"/news_id=[^0-9]+/i"; '
            r'metadata:policy max-detect-ips drop; service:http; '
            r'reference:bugtraq,21668; reference:cve,2006-6504; '
            r'classtype:attempted-user; sid:15999; rev:9; )'
        )

        rule = Rule.from_string(rule_str)

        rule_mutator = RuleMutator(mutate_strategy='obfuscate')

        for _request, _response in rule_mutator.mutate([rule]):
            print(_request.decode('latin-1'))
            print(f'---------------------------------------------\n---------------------------------------------\n')

            print(_response.decode('latin-1'))
            print(f'---------------------------------------------\n---------------------------------------------\n')

    def test_rule_random_strategy(self):
        rule_str = (
            r'alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any ( '
            r'msg:"BROWSER-FIREFOX Mozilla products frame comment objects manipulation memory corruption attempt"; '
            r'flow:to_client,established; file_data; '
            r'isdataat:1300;'
            r'content: "hello"; '  # added
            r'content: "world!", distance 1, within 7;'  # added
            r'content:"bb.appendChild|28|fr.childNodes[4]|29 3B|",fast_pattern,nocase, distance 7; '  # add distance 7
            r'metadata:policy max-detect-ips drop; service:http; '
            r'reference:bugtraq,21668; reference:cve,2006-6504; '
            r'classtype:attempted-user; sid:15999; rev:9; )'
        )
        rule = Rule.from_string(rule_str)

        rule_mutator = RuleMutator(mutate_strategy='random')

        for _request, _response in rule_mutator.mutate([rule]):
            print(_request.decode('latin-1'))
            print(f'---------------------------------------------\n---------------------------------------------\n')

            print(_response.decode('latin-1'))
            print(f'---------------------------------------------\n---------------------------------------------\n')