import re

from rule.options import Option


class Pcre(Option):
    """
    The pcre rule option matches regular expression strings against packet data.

    e.g. pcre:!"/^file\x3a\x2f\x2f[^\n]{400}/mi";

    Format:
        pcre:[!]"/pcre_string/[flag…]";

    @see https://docs.snort.org/rules/options/payload/pcre#pcre

    Usage:
    --------
    >>> test = r'"/^file\x3a\x2f\x2f[^\n]{400}/mi"'
    >>> pcre_opt = Pcre.from_string(test)
    >>> print(pcre_opt.items())
    >>> # dict_items([('match', '^file\\x3a\\x2f\\x2f[^\\n]{400}'), ('negated', False), ('flags', 'mi'), ('i', True),
    >>> # ('s', False), ('m', True), ('x', False), ('A', False), ('E', False), ('G', False), ('O', False),
    >>> # ('R', False)])
    """
    PCRE_PATTERN = re.compile(r'^(?P<negated>!)?"(?P<match>/.*/)(?P<flags>[ismxAEGOR]*)"$')  # greedy match

    def __init__(self, raw: str):
        super(Pcre, self).__init__()
        self.raw = raw
        self["match"] = None
        self["negated"] = False
        self["flags"] = None
        self["i"] = False
        self["s"] = False
        self["m"] = False
        self["x"] = False
        self["A"] = False
        self["E"] = False
        self["G"] = False
        self["O"] = False
        self["R"] = False

    def __str__(self):
        return f"pcre:{self.raw};"

    @classmethod
    def from_string(cls, raw: str):
        raw.strip()
        pcre = cls(raw)
        m = cls.PCRE_PATTERN.match(raw)
        if not m:
            raise Exception(f"Invalid pcre option: {raw}")

        if m.group("negated") is not None:
            pcre["negated"] = True
        else:
            pcre["negated"] = False

        match = m.group("match")
        pcre["match"] = match[1:-1]

        pcre["flags"] = m.group("flags")
        pcre["i"] = pcre.i
        pcre["s"] = pcre.s
        pcre["m"] = pcre.m
        pcre["x"] = pcre.x
        pcre["A"] = pcre.A
        pcre["E"] = pcre.E
        pcre["G"] = pcre.G
        pcre["O"] = pcre.O
        pcre["R"] = pcre.R

        return pcre

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
    def x(self):
        """
        specifies that whitespace data characters in the pattern are ignored
        except when escaped or inside a character class
        """
        return "X" in self["flags"]

    @property
    def A(self):
        """
        specifies the pattern must match only at the start of the buffer
        (same as specifying the '^' character)
        """
        return "A" in self["flags"]

    @property
    def E(self):
        """
        sets '$' to match only at the end of the subject string
        """
        return "E" in self["flags"]

    @property
    def G(self):
        """
        inverts the "greediness" of the quantifiers so that they are
        not greedy by default, but become greedy if followed by '?'
        """
        return "G" in self["flags"]

    @property
    def O(self):
        """
        overrides the configured pcre match limit and pcre match
        limit recursion for this expression
        """
        return "O" in self["flags"]

    @property
    def R(self):
        """
        start the regex search from the end of the last match
        instead of start of buffer
        """
        return "R" in self["flags"]

    @property
    def literal_match(self) -> str | None:
        if self['match'] is None:
            return None

        # Decode escape characters represented by '\x' in PCRE
        def decode_pcre(match) -> str:
            hex_value = match.group(1)
            int_value = int(hex_value, 16)
            return chr(int_value)

        return re.sub(r'\\x([0-9a-fA-F]{2})', decode_pcre, self['match'])


if __name__ == '__main__':
    test = r'"/^file\x3a\x2f\x2f[^\n]{400}/mi"'
    pcre_opt = Pcre.from_string(test)

    print(f'raw match: {pcre_opt["match"]!r}')
    print(f'literal match: {pcre_opt.literal_match!r}')
    print(f'Bytes match: {pcre_opt.literal_match.encode("utf-8")}')

    print(f'Repr(pcre):\n{pcre_opt.items()}')
