import pathlib
import unittest

from generation import PassThroughMutator, BlendingMutator, RepetitionMutator, ObfuscationMutator
from rule import Rule, RuleSet


class TestRuleMutator(unittest.TestCase):

    def setUp(self):
        self.ruleset = RuleSet.from_file(
            str(pathlib.Path(__file__).parent.parent / 'resources' / 'rules' / 'snort3-community.rules')
        )

        # FTP rule with only one content
        self.rule_1 = Rule.from_string(
            r'alert tcp $EXTERNAL_NET any -> $HOME_NET 21 ( '
            r'msg:"PROTOCOL-FTP authorized_keys"; '
            r'flow:to_server,established; '
            r'content:"authorized_keys",fast_pattern,nocase; '
            r'metadata:ruleset community; '
            r'service:ftp; '
            r'classtype:suspicious-filename-detect; '
            r'sid:1927; rev:8; )'
        )
        # HTTP rule with a pcre and a non-redundant content
        self.rule_2 = Rule.from_string(
            r'alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any ( '
            r'msg:"BROWSER-FIREFOX Mozilla products frame comment objects manipulation memory corruption attempt"; '
            r'flow:to_client,established; '
            r'file_data; '
            r'content:"/msadc/msadc.dll",fast_pattern,nocase; '
            r'pcre:"/news_id=[^0-9]+/i"; '
            r'metadata:policy max-detect-ips drop; '
            r'service:http; '
            r'reference:bugtraq,21668; reference:cve,2006-6504; '
            r'classtype:attempted-user; '
            r'sid:15999; rev:9; )'
        )
        # Multi-protocol rule with flowbits, a pcre and a redundant content
        self.rule_3 = Rule.from_string(
            r'alert tcp $EXTERNAL_NET $FILE_DATA_PORTS -> $HOME_NET any ( '
            r'msg:"FILE-MULTIMEDIA RealNetworks RealPlayer playlist file URL overflow attempt"; '
            r'flow:to_client,established; '
            r'flowbits:isset,file.realplayer.playlist; '  # flowbits
            r'file_data; '
            r'content:"file|3A|//",nocase; '
            r'pcre:"/^file\x3a\x2f\x2f[^\n]{400}/ims"; '
            r'metadata:policy max-detect-ips drop,ruleset community; '
            r'service:ftp-data,http,imap,pop3; '
            r'reference:bugtraq,13264; reference:bugtraq,9579; reference:cve,2004-0258; '
            r'reference:cve,2004-0550; reference:cve,2005-0755; '
            r'classtype:attempted-user; '
            r'gid:1; sid:2438; rev:24; )'
        )
        # SIP rule with a sip_method
        self.rule_4 = Rule.from_string(
            r'alert udp $EXTERNAL_NET any -> $SIP_SERVERS $SIP_PORTS ( '
            r'msg:"PROTOCOL-VOIP inbound INVITE message"; '
            r'flow:to_server; '
            r'content:"INVITE",fast_pattern,nocase; '
            r'sip_method:invite; '
            r'metadata:policy max-detect-ips drop,ruleset community; '
            r'service:sip; '
            r'reference:url,www.ietf.org/rfc/rfc3261.txt; classtype:protocol-command-decode; '
            r'sid:11968; rev:8; )'
        )
        # SIP rule with a sip_header
        self.rule_5 = Rule.from_string(
            r'alert udp $EXTERNAL_NET any -> $SIP_SERVERS $SIP_PORTS ( '
            r'msg:"PROTOCOL-VOIP Contact header format string attempt"; '
            r'flow:to_server; '
            r'content:"Contact|3A|",fast_pattern,nocase; '
            r'sip_header; '
            r'pcre:"/^Contact\x3A\s*[^\r\n%]*%/ims"; '
            r'metadata:policy max-detect-ips drop; '
            r'service:sip; '
            r'reference:url,www.ee.oulu.fi/research/ouspg/protos/testing/c07/sip/; '
            r'reference:url,www.ietf.org/rfc/rfc3261.txt; '
            r'classtype:attempted-dos; '
            r'sid:11990; rev:7; )'
        )

    def test_passthrough_mutator(self):
        mutator = PassThroughMutator(
            ruleset=self.ruleset,
        )
        for request, response in mutator.generate(self.rule_1, proto='ftp'):
            print(f'request:\n{request.decode("utf-8")}')
            print('=======================')
            print(f'response:\n{response.decode("utf-8")}')
            print('=======================')

        for request, response in mutator.generate(self.rule_3, proto='http'):
            print(f'request:\n{request.decode("utf-8")}')
            print('=======================')
            print(f'response:\n{response.decode("utf-8")}')
            print('=======================')

        for request, response in mutator.generate(self.rule_5, proto='sip'):
            print(f'request:\n{request.decode("utf-8")}')
            print('=======================')
            print(f'response:\n{response.decode("utf-8")}')
            print('=======================')

    def test_blending_mutator(self):
        mutator = BlendingMutator(
            ruleset=self.ruleset,
        )
        for request, response in mutator.generate(self.rule_2, self.rule_3, proto='http'):
            print(f'request:\n{request.decode("utf-8")}')
            print('=======================')
            print(f'response:\n{response.decode("utf-8")}')
            print('=======================')

    def test_repetition_mutator(self):
        mutator = RepetitionMutator(
            ruleset=self.ruleset,
            mode='block-wise',
            repeat_times=3,
            min_repeat_times=2,
            max_repeat_times=10
        )

        for request, response in mutator.generate(self.rule_1, proto='ftp',):
            print(f'request:\n{request.decode("utf-8")}')
            print('=======================')
            print(f'response:\n{response.decode("utf-8")}')
            print('=======================')

    def test_obfuscation_mutator(self):
        mutator = ObfuscationMutator(
            ruleset=self.ruleset,
            replace_times=10,
            insert_times=3,
            min_obfuscate_times=2,
            max_obfuscate_times=10
        )

        for request, response in mutator.generate(self.rule_3, proto='http',):
            print(f'request:\n{request.decode("utf-8")}')
            print('=======================')
            print(f'response:\n{response.decode("utf-8")}')
            print('=======================')