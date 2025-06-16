import re

from preprocessing.rule_parser.options import Option


class Bufferlen(Option):
    """
    The bufferlen option enables rule-writers to check the length (byte) of a given buffer.

    Format:
        bufferlen:[<|>|=|!|<=|>=]length[,relative];
        bufferlen:min_length{<>|<=>}max_length[,relative];

    Example:
        bufferlen:10,relative;
        bufferlen:2<=>10;

    @see https://docs.snort.org/rules/options/payload/bufferlen#bufferlen

    Usage:
    --------
    >>> test = r'4<=>10,relative'
    >>> buffer_len = Bufferlen.from_string(test)
    >>> print(buffer_len.items())
    >>> # dict_items([('length', None), ('min_length', 4), ('max_length', 10), ('sign', '<=>'), ('relative', True)])
    """

    SINGLE_VALUE_PATTERN = re.compile(r'^(?P<sign><|>|=|!|<=|>=)?(?P<length>\d+)(?P<relative>,relative)?$')
    RANGE_PATTERN = re.compile(r'^(?P<minlen>\d+)(?P<sign>(<>|<=>))(?P<maxlen>\d+)(?P<relative>,relative)?$')

    def __init__(self, raw: str):
        super(Bufferlen, self).__init__()
        self.raw = raw
        self._range = False
        self["length"] = None
        self["min_length"] = None
        self["max_length"] = None
        self["sign"] = None
        self["relative"] = False

    def __str__(self):
        return f"bufferlen:{self.raw};"

    def _match_single_value_pattern(self) -> bool:
        m = self.SINGLE_VALUE_PATTERN.match(self.raw)
        if not m:
            return False
        self._range = False
        if m.group("sign") is not None:
            self["sign"] = m.group("sign")
        if m.group("relative") is not None:
            self["relative"] = True
        self["length"] = int(m.group("length"))
        return True

    def _match_range_pattern(self) -> bool:
        m = self.RANGE_PATTERN.match(self.raw)
        if not m:
            return False
        self._range = True
        if m.group("relative") is not None:
            self["relative"] = True
        self["min_length"] = int(m.group("minlen"))
        self["sign"] = m.group("sign")
        self["max_length"] = int(m.group("maxlen"))
        return True

    @classmethod
    def from_string(cls, raw: str):
        bufferlen = cls(raw)

        if not bufferlen._match_single_value_pattern():
            if not bufferlen._match_range_pattern():
                raise Exception(f"Invalid bufferlen option: {raw}")

        return bufferlen


if __name__ == '__main__':
    test = r'4<=>10,relative'
    bufferlen = Bufferlen.from_string(test)
    print(bufferlen.items())
