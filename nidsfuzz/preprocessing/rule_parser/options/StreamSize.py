import re

from preprocessing.rule_parser.options import Option


class StreamSize(Option):
    """
    The stream_size rule option is used to check the stream size of a given TCP session.

    Note: By default, the specified value gets checked against both the client and
    server's TCP sequence numbers, marking it as a "match" if either check passes.

    Format:
        stream_size:[<|>|=|!|<=|>=]bytes[,{either|to_server|to_client|both}];
        stream_size:min_bytes{<>|<=>}max_bytes[,{either|to_server|to_client|both}];

    Example:
        stream_size:=125,to_server;
        stream_size:0<>100,both;

    @see https://docs.snort.org/rules/options/non_payload/stream_size

    Usage:
    --------
    >>> test = r'0<>100,both'
    >>> test_opt = StreamSize.from_string(test)
    >>> print(test_opt.items())
    >>> # dict_items([('sign', '<>'), ('bytes', None), ('min_bytes', '0'), ('max_bytes', '100'), ('direction', 'both')])
    """

    SINGLE_VALUE_PATTERN = re.compile(r'^'
                                      r'(?P<sign><|>|=|!|<=|>=)?'
                                      r'(?P<bytes>\d+)'
                                      r',?(?P<direction>either|to_server|to_client|both)?'
                                      r'$')
    RANGE_PATTERN = re.compile(r'^'
                               r'(?P<min_bytes>\d+)'
                               r'(?P<sign><>|<=>)'
                               r'(?P<max_bytes>\d+)'
                               r',?(?P<direction>either|to_server|to_client|both)?'
                               r'$')

    def __init__(self, raw: str):
        super().__init__()
        self.raw = raw
        self._range = False
        self["sign"] = None
        self["bytes"] = None
        self["min_bytes"] = None
        self["max_bytes"] = None
        self["direction"] = "either"

    def __str__(self):
        return f"stream_size:{self.raw};"

    def _match_single_value_pattern(self) -> bool:
        m = self.SINGLE_VALUE_PATTERN.match(self.raw)
        if not m:
            return False
        self._range = False
        if m.group("sign") is not None:
            self["sign"] = m.group("sign")
        if m.group("direction") is not None:
            self["direction"] = m.group("direction")
        self["bytes"] = m.group("bytes")
        return True

    def _match_range_pattern(self) -> bool:
        m = self.RANGE_PATTERN.match(self.raw)
        if not m:
            return False
        self._range = True
        if m.group("direction") is not None:
            self["direction"] = m.group("direction")
        self["min_bytes"] = m.group("min_bytes")
        self["sign"] = m.group("sign")
        self["max_bytes"] = m.group("max_bytes")
        return True

    @classmethod
    def from_string(cls, raw: str):
        stream_size = cls(raw)

        if not stream_size._match_single_value_pattern():
            if not stream_size._match_range_pattern():
                raise Exception(f"Invalid stream_size option: {raw}")

        return stream_size


if __name__ == '__main__':
    test = r'0<>100,both'
    test_opt = StreamSize.from_string(test)
    print(test_opt.items())
