import re

from . import Option


class Isdataat(Option):
    """
    The isdataat rule option verifies the payload data exists
     at a specified location.

     Format:
        isdataat:[!]location[,relative];

    Example:
        isdataat:29,relative;

    @see https://docs.snort.org/rules/options/payload/isdataat#isdataat

    Usage:
    --------
    >>> test_str = r'!29,relative'
    >>> isdataat_opt = Isdataat.from_string(test_str)
    >>> print(isdataat_opt.items())
    >>> # dict_items([('negated', True), ('location', 29), ('relative', True)])
    """

    PATTERN = re.compile(r'^(?P<negated>!)?\s*(?P<location>\d+)\s*(?P<relative>,\s*relative)?$')

    def __init__(self, raw: str):
        super().__init__()
        self.raw = raw
        self["negated"] = False
        self["location"] = None
        self["relative"] = False

    def __str__(self):
        return f"isdataat:{self.raw};"

    @classmethod
    def from_string(cls, raw: str):
        isdataat = cls(raw)

        m = isdataat.PATTERN.match(raw)
        if not m:
            raise Exception(f"Invalid isdataat option: {raw}")
        if m.group("negated") is not None:
            isdataat["negated"] = True
        if m.group("relative") is not None:
            isdataat["relative"] = True

        isdataat["location"] = int(m.group("location"))

        return isdataat


if __name__ == '__main__':
    test_str = r'!29,relative'
    isdataat_opt = Isdataat.from_string(test_str)
    print(isdataat_opt.items())
