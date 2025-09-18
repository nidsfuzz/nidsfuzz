import re

from rule.constants.StickyBuffer import StickyBuffer
from rule.options import Option, Flow, Content, Isdataat, Pcre, Bufferlen, Dsize, ByteTest


class Rule:
    """
    Methods:
    --------
    is_valid(rule_str: str) -> bool:
        Validate whether the string conforms to the rule definition format.

    from_string(cls, rule_str: str) -> 'Rule':
        Creates a Rule instance from a string.

    get(self, opt_name: str) -> str:
        Gets the value for the given option in the rule.


    Example Usage:
    --------
    Check if the provided string satisfies the grammer constraints of Snort rule:

    >>> rule_str = (r'# alert tcp $EXTERNAL_NET any -> $HOME_NET 21 ( msg:"PROTOCOL-FTP .rhosts"; flow:to_server,'
    >>>         r'established; content:".rhosts"; metadata:policy max-detect-ips drop,ruleset community; '
    >>>         r'service:ftp; classtype:suspicious-filename-detect; sid:335; rev:16; )')
    >>> is_valid = Rule.is_valid(rule_str)  # true

    Create a Rule object from a valid string:

    >>> rule = Rule.from_string(rule_str)

    Retrieve the signatures (options) from the Rule object:

    >>> opt_msg = rule.get('msg')  # "PROTOCOL-FTP .rhosts"
    >>> opt_flow = rule.get('flow') # to_server,established
    >>> opt_content = rule.get('content') # ['".rhosts"',]
    """

    # A basic Snort rule grammar
    _rule_pattern = re.compile(r"^(?P<enabled>#)*[\s#]*"
                               r"(?P<raw>"
                               r"(?P<header>[^()]+)"
                               r"\((?P<options>.*)\)"
                               r"$)")

    def __init__(self,
                 raw: str,
                 activated: bool,
                 action: str,
                 proto: str,
                 src_ip: str,
                 src_port: str,
                 direction: str,
                 dst_ip: str,
                 dst_port: str,
                 options: str):
        self._raw = raw
        self._activated = activated
        self._action = action
        self._proto = proto
        self._src_ip = src_ip
        self._src_port = src_port
        self._direction = direction
        self._dst_ip = dst_ip
        self._dst_port = dst_port
        self._rule_body = RuleBody(options)

    def __str__(self) -> str:
        """
        Provide a user-friendly string representation of the rule.
        """
        return f'{"# " if not self._activated else ""}{self._action} {self._proto} {self._src_ip} {self._src_port} ' \
               f'{self._direction} {self._dst_ip} {self._dst_port} ( {self._rule_body} )'

    def __repr__(self) -> str:
        """
        Provides a more detailed, developer-oriented string representation
        of the rule, typically useful for debugging.
        """
        return str(self)

    def __hash__(self):
        return hash(str(self))

    def __eq__(self, other):
        if not isinstance(other, Rule):
            return False
        return str(self) == str(other)

    @property
    def fuzzy_signature(self) -> str:
        full_signature = str(self)

        fuzzy_signature = re.search(r'\((.*)\)', full_signature)
        if not fuzzy_signature:
            return ''

        # noteworthy_options = RuleBody.sig_options.keys()
        # noteworthy_options_pattern = r'\s*(?:' + '|'.join(noteworthy_options) + r')\s*:\s*(.*?;)'
        #
        # matches = re.findall(noteworthy_options_pattern, fuzzy_signature.group(1))
        # return  ''.join(matches)

        ignored_options = [
            'msg',
            'flow',
            'metadata',
            'service',
            'reference',
            'classtype',
            'gid',
            'sid',
            'rev'
        ]
        ignored_options_pattern = r'\s*(?:' + '|'.join(ignored_options) + r'):.*?;'
        fuzzy_signature = re.sub(ignored_options_pattern, '', fuzzy_signature.group(1))

        remove_option_name = r'\s*[a-zA-Z]*?\s*:\s*'
        fuzzy_signature = re.sub(remove_option_name, '', fuzzy_signature).strip()

        return fuzzy_signature

    @property
    def activated(self) -> bool:
        return self._activated

    @property
    def protocol(self) -> str:
        return self._proto

    @property
    def port(self) -> str:
        """@https://docs.snort.org/rules/options/non_payload/flow"""
        if self.get('flow') is None:
            return self._dst_port
        else:
            flow = Flow.from_string(self.get('flow'))
            if flow['to_client'] or flow['from_server']:
                return self._src_port
            elif flow['to_server'] or flow['from_client']:
                return self._dst_port
            else:
                raise RuntimeError(f'Failed to parse port.')

    @property
    def service(self) -> str:
        if self.get('service') is None:
            return self.protocol
        return self.get('service')

    @property
    def signature(self) -> dict[str, list[Option]]:
        """
        return a dict where the key is the sticky buffer
        and the value is a list of corresponding options.
        """
        return self._rule_body.signature

    @property
    def id(self) -> str:
        """
        @https://docs.snort.org/rules/options/general/gid
        @https://docs.snort.org/rules/options/general/sid
        @https://docs.snort.org/rules/options/general/rev
        """
        gid = self.get('gid') if self.get('gid') else "1"
        sid = self.get('sid') if self.get('sid') else ""
        rev = self.get('rev') if self.get('rev') else "1"
        return f"{gid}:{sid}:{rev}"

    @classmethod
    def from_string(cls, rule_str: str) -> 'Rule':
        """
        Create a rule object from a string representation.

        TODO: only Traditional Rules are implemented, and three new rule types, i.e., Service Rules,
        File Rules, and File Identification Rules, have not yet been implemented.

        @see https://docs.snort.org/rules/headers/new_header_types
        """
        # remove leading and trailing whitespace (spaces, tabs, newlines) from a string.
        rule_str = rule_str.strip()

        m = cls._rule_pattern.match(rule_str)
        if not m:
            return None

        action = None
        proto = None
        src_ip = None
        src_port = None
        direction = None
        dst_ip = None
        dst_port = None

        if m.group('enabled') == "#":
            enabled = False
        else:
            enabled = True

        header = m.group("header").strip()

        # if a decoder rule, the header will be one word.
        if len(header.split(" ")) == 1:
            action = header
        else:
            states = ["action", "proto", "src_ip", "src_port", "direction", "dst_ip", "dst_port"]
            state = 0
            rem = header
            while state < len(states):
                if not rem:
                    return None
                if rem[0] == "[":
                    end = rem.find("]")
                    if end < 0:
                        return None
                    token = rem[:end + 1].strip()
                    rem = rem[end + 1:].strip()
                else:
                    end = rem.find(" ")
                    if end < 0:
                        token = rem
                        rem = ""
                    else:
                        token = rem[:end].strip()
                        rem = rem[end:].strip()

                if states[state] == "action":
                    action = token
                elif states[state] == "proto":
                    proto = token
                elif states[state] == "src_ip":
                    src_ip = token
                elif states[state] == "src_port":
                    src_port = token
                elif states[state] == "direction":
                    direction = token
                elif states[state] == "dst_ip":
                    dst_ip = token
                elif states[state] == "dst_port":
                    dst_port = token

                state += 1

        options = m.group("options").strip()

        raw = m.group("raw").strip()

        return cls(raw, enabled, action, proto, src_ip, src_port, direction, dst_ip, dst_port, options)

    @staticmethod
    def is_valid(rule_str: str) -> bool:
        """
        Check if the given string is a valid rule.
        """
        if not isinstance(rule_str, str):
            raise TypeError(f"rule_str must be of type str, not {type(rule_str)}")
        return Rule._rule_pattern.match(rule_str) is not None

    def get(self, opt_name: str, default_value=None) -> str:
        """
        Get the value of an option from the rule.
        """
        return self._rule_body.get(opt_name, default_value)


def find_opt_end(options: str) -> int:
    """ Find the end of an option (;) handling escapes. """
    offset = 0

    while True:
        i = options[offset:].find(";")
        if options[offset + i - 1] == "\\":
            offset += 2
        else:
            return offset + i


class RuleBody(dict):
    """
    Snort evaluates payload options against a given buffer, it keeps track of
    its current location there with a detection-offset-end (DOE) pointer
    (also sometimes referred to as a cursor). By default, this pointer points
    to the start of the current buffer, but some rule options will "move" this
    pointer forward and backwards, which allow for the use of relative payload
    options.

    By default, rule options are evaluated against data present in the pkt_data
    buffer. Looking for data in one of the other buffers is done by using what
    are called "sticky buffers", which are rule options that, when set, move
    the DOE pointer to the start of that particular buffer. Then, all subsequent
    payload options will be looked for in that buffer unless some other sticky
    buffer is specified.

    @see https://docs.snort.org/rules/options/payload/index.html
    """

    sig_options = {
        "content": Content,
        "isdataat": Isdataat,
        "pcre": Pcre,
        "bufferlen": Bufferlen,
        "dsize": Dsize,
        "byte_test": ByteTest
    }

    def __init__(self, raw: str):
        dict.__init__(self)
        self._raw = raw
        # Preserves the order in which each option appears in a Snort rule.
        self["options"] = []
        # Groups options according to their applied sticky buffer
        # Note: starting from Python 3.7, dict guarantees insertion order.
        self.signature: dict[str, list[Option]] = {}
        # TODO: Some rule options may appear multiple times in a Snort rule
        self._list_options = ["content", "pcre", "isdataat", "reference", "flowbits", "bufferlen", "byte_test"]
        # Groups options according to their option name
        self._parse(raw)

    def _parse(self, options: str):
        """
        Please refer to idstools.rule.py for details
        """

        cur_buffer = "pkt_data"

        while True:
            if not options:
                break
            index = find_opt_end(options)
            if index < 0:
                raise Exception(f"end of option (;) not found: {options}")
            option = options[:index].strip()
            options = options[index + 1:].strip()

            if option.find(":") > -1:
                name, val = [x.strip() for x in option.split(":", 1)]
            else:
                name = option
                val = None

            # Groups options according to their applied sticky buffer
            if name in StickyBuffer.all():
                cur_buffer = name
            elif name in self.sig_options.keys():
                option = self.sig_options[name].from_string(val)
                self.signature.setdefault(cur_buffer, []).append(option)

            # Preserves the order in which each option appears in a Snort rule.
            self["options"].append({
                "name": name,
                "value": val,
            })

            # Groups options according to their option name
            if name in self._list_options:
                self.setdefault(name, []).append(val)
            elif name == "msg":
                # if val.startswith('"') and val.endswith('"'):
                #     val = val[1:-1]
                self["msg"] = val
            else:
                self[name] = val

    def __str__(self):
        """Rebuild the rule options from the list of options."""
        options = []
        for option in self["options"]:
            if option["value"] is None:
                options.append(option["name"])
            else:
                options.append("%s:%s" % (option["name"], option["value"]))
        return "%s;" % "; ".join(options)

    def __repr__(self):
        res = ""
        for sticky_buffer, options in self.signature.items():
            res += f"{sticky_buffer}:"
            for opt in options:
                res += f"    {str(opt)}"
            else:
                res += "\n"
        return res


if __name__ == "__main__":
    # import idstools.rule

    # rule_str = (r'# alert tcp $EXTERNAL_NET any -> $HOME_NET 21 ( msg:"PROTOCOL-FTP .rhosts"; flow:to_server,'
    #             r'established; content:".rhosts"; metadata:policy max-detect-ips drop,ruleset community; '
    #             r'service:ftp; classtype:suspicious-filename-detect; sid:335; rev:16; )')

    rule_str = (r'alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any '
                r'( '
                r'msg:"BROWSER-FIREFOX Mozilla Products SVG text content element getCharNumAtPosition use after free attempt"; '
                r'flow:to_client,established; '
                r'file_data; '
                r'content:"<svg",nocase; '
                r'content:"<text id",within 400,nocase; '
                r'content:"getElementByID",within 300,nocase; '
                r'content:"removeChild",within 100; '
                r'content:"getCharNumAtPosition",within 200,nocase; '
                r'pcre:"/removeChild\((?<element>\w{1,20})\).*(?P=element)\.getCharNumAtPosition/ims"; '
                r'metadata:policy max-detect-ips drop,policy security-ips drop; '
                r'service:ftp-data,http,imap,pop3; '
                r'sid:29503; '
                r'rev:5; '
                r')')

    rule = Rule.from_string(rule_str)

    print(rule)

    print(f"Protocol: {rule.protocol}")
    print(f"Port: {rule.port}")
    print(f"Service: {rule.service}")
    print(f"ID: {rule.id}")

    print(repr(rule.signature))

    # test str method
    assert str(rule) == rule_str

    print(f"Msg Option: {rule.get('msg')}")
    print(f"Content Option: {rule.get('content')}")
    print(f"Flow Option: {rule.get('flow')}")
    print(f"Flowbits Option: {rule.get('flowbits')}")

    # test the override equal method
    rule2 = Rule.from_string(rule_str)
    assert rule == rule2
