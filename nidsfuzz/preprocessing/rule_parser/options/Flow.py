from . import Option


class Flow(Option):
    """
    The flow option is used to check session properties of a given packet.
    There are four main property categories that one can check with this option:
        * Category 1: Whether it's from a client to a server or from a server to a client.
        * Category 2: Whether the packet is part of an established TCP connection or not.
        * Category 3: Whether the packet is a reassembled packet or not.
        * Category 4: Whether the packet is a rebuilt frag packet or not.

    Format:
        flow:[{established|not_established|stateless}][,{to_client|to_server|from_client|from_server}] \
        [,{no_stream|only_stream}][,{no_frag|only_frag}];

    Example:
        flow:to_server,established;

    @see https://docs.snort.org/rules/options/non_payload/flow

    Usage:
    --------
    >>> test = r'to_server,established'
    >>> test_opt = Flow.from_string(test)
    >>> print(test_opt.items())
    >>> # dict_items([('to_client', False), ('to_server', True), ('from_client', False), ('from_server', False),
    >>> # ('established', True), ('not_established', False), ('stateless', False), ('no_stream', False),
    >>> # ('only_stream', False), ('no_frag', False), ('only_frag', False)])
    """

    def __init__(self, raw: str):
        super().__init__()
        self.raw = raw
        self["to_client"] = False
        self["to_server"] = False
        self["from_client"] = False
        self["from_server"] = False
        self["established"] = False
        self["not_established"] = False
        self["stateless"] = False
        self["no_stream"] = False
        self["only_stream"] = False
        self["no_frag"] = False
        self["only_frag"] = False

    def __str__(self):
        return f"flow:{self.raw};"

    def format_check(self):
        if [self["to_client"], self["to_server"], self["from_client"], self["from_server"]].count(True) > 1:
            return False
        if [self["established"], self["not_established"], self["stateless"]].count(True) > 1:
            return False
        if [self["no_stream"], self["only_stream"]].count(True) > 1:
            return False
        if [self["no_frag"], self["only_frag"]].count(True) > 1:
            return False
        return True

    @classmethod
    def from_string(cls, raw: str):
        flow = cls(raw)

        for argument in raw.split(","):
            argument = argument.strip()
            if argument not in flow:
                raise Exception(f"Invalid flow argument: {argument}")
            else:
                flow[argument] = True

        if flow.format_check():
            return flow
        else:
            raise Exception(f"Invalid flow option: {str(raw)}")


if __name__ == '__main__':
    test = r'to_server,established'
    test_opt = Flow.from_string(test)
    print(test_opt.items())
