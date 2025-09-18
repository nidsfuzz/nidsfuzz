import re

from rule.options import Option


class Regex(Option):
    """
    The regex rule option matches regular expressions against payload data
    via the hyperscan search engine.

    Format:
        regex:"/regex_string/[flag…]"[,fast_pattern][,nocase];

    Example:
        regex:"/^file\x3a\x2f\x2f[^\n]{400}/mi",fast_pattern;

    @see https://docs.snort.org/rules/options/payload/regex#regex

    Usage:
    --------
    >>> test = r'"/^file\x3a\x2f\x2f[^\n]{400}/mi",nocase'
    >>> regex_opt = Regex.from_string(test)
    >>> print(regex_opt.items())
    >>> # dict_items([('match', '^file\\x3a\\x2f\\x2f[^\\n]{400}'), ('flags', 'mi'), ('fast_pattern', False),
    >>> # ('nocase', True), ('i', True), ('s', False), ('m', True), ('R', False)])
    """

    PATTERN = re.compile(r'^"(?P<match>/.*/)(?P<flags>[ismR]*)"(?P<fast_pattern>,fast_pattern)?(?P<nocase>,nocase)?$')

    def __init__(self, raw: str):
        super().__init__()
        self.raw = raw
        self["match"] = None
        self["flags"] = None
        self["fast_pattern"] = False
        self["nocase"] = False
        self["i"] = False
        self["s"] = False
        self["m"] = False
        self["R"] = False

    def __str__(self):
        return f"regex:{self.raw};"

    @classmethod
    def from_string(cls, raw: str):
        regex = cls(raw)
        m = regex.PATTERN.match(raw)
        if not m:
            raise Exception(f"Invalid regex option: {raw}")

        regex["match"] = m.group("match")[1:-1]
        regex["flags"] = m.group("flags")
        if m.group("fast_pattern") is not None:
            regex["fast_pattern"] = True
        if m.group("nocase") is not None:
            regex["nocase"] = True

        regex["i"] = regex.i
        regex["s"] = regex.s
        regex["m"] = regex.m
        regex["R"] = regex.R

        return regex

    @property
    def i(self):
        """
        case insensitive
        """
        return "i" in self["flags"]

    @property
    def s(self):
        """
        include newlines in the dot metacharacter
        """
        return "s" in self["flags"]

    @property
    def m(self):
        """
        When m is set, '^' and '$' match immediately following or immediately
        before any newline in the buffer, as well as the very start and very
        end of the buffer.
        """
        return "m" in self["flags"]

    @property
    def R(self):
        """
        start the regex search from the end of the last match
        instead of start of buffer
        """
        return "R" in self["flags"]


if __name__ == '__main__':
    test = r'"/^file\x3a\x2f\x2f[^\n]{400}/mi",nocase'
    regex_opt = Regex.from_string(test)
    print(regex_opt.items())

