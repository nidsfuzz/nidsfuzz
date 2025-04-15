import re

from . import Option


class Dsize(Option):
    """
    The dsize rule option is used to test a packet's payload size.

    Format:
        dsize:[<|>|=|!|<=|>=]size;
        dsize:min_size{<>|<=>}max_size;

    Example:
        dsize:>10000;
        dsize:300<>400;

    @see https://docs.snort.org/rules/options/payload/dsize#dsize

    Usage:
    --------
    >>> test = r'300<>400'
    >>> dsize = Dsize.from_string(test)
    >>> print(dsize.items())
    >>> # dict_items([('size', None), ('min_size', 300), ('max_size', 400), ('sign', '<>')])
    """
    SINGLE_VALUE_PATTERN = re.compile(r'^(?P<sign><|>|=|!|<=|>=)?(?P<size>\d+)$')
    RANGE_PATTERN = re.compile(r'^(?P<minsize>\d+)(?P<sign>(<>|<=>))(?P<maxsize>\d+)$')

    def __init__(self, raw: str):
        super().__init__()
        self.raw = raw
        self._range = False
        self["size"] = None
        self["min_size"] = None
        self["max_size"] = None
        self["sign"] = None

    def __str__(self):
        return f"dsize:{self.raw};"

    def _match_single_value_pattern(self) -> bool:
        m = self.SINGLE_VALUE_PATTERN.match(self.raw)
        if not m:
            return False
        self._range = False
        self["sign"] = m.group("sign")
        self["size"] = int(m.group("size"))
        return True

    def _match_range_pattern(self) -> bool:
        m = self.RANGE_PATTERN.match(self.raw)
        if not m:
            return False
        self._range = True
        self["min_size"] = int(m.group("minsize"))
        self["sign"] = m.group("sign")
        self["max_size"] = int(m.group("maxsize"))
        return True

    @classmethod
    def from_string(cls, raw: str):
        dsize = cls(raw)

        if not dsize._match_single_value_pattern():
            if not dsize._match_range_pattern():
                raise ValueError(f"Invalid dsize option: {raw}")

        return dsize


if __name__ == '__main__':
    test = r'300<>400'
    dsize_opt = Dsize.from_string(test)
    print(dsize_opt.items())
