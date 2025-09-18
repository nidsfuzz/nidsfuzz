import re

from utils import hex2str
from rule.options import Option


class Content(Option):
    """
    A rule can contain multiple content matches, and each match is evaluated
    in the order they are declared in the rule.

    e.g. content:!"Hello, this is Quagga:Bob",fast_pattern,nocase;

    Note: certain characters must be either escaped (with '\' characters)
    or encoded in hex. These are: ';', '\', and '"'.

    @see: https://docs.snort.org/rules/options/payload/content

    Usage:
    --------
    >>> test = r'!"Hello, this is Quagga:Bob",fast_pattern,nocase'
    >>> content = Content.from_string(test)
    >>> print(content.items())
    >>> # dict_items([('match', 'Hello, this is Quagga:Bob'), ('nocase', True), ('rawbytes', False),
    >>> # ('fast_pattern', True), ('fast_pattern_offset', None), ('fast_pattern_length', None), ('offset', None),
    >>> # ('depth', None), ('distance', None), ('within', None), ('negated', True)])
    """

    CONTENT_PATTERN = re.compile(r'^(?P<match>!?".+"),?\s*(?P<modifiers>.*)')  # greedy match

    def __init__(self, raw: str):
        super(Content, self).__init__()
        self.raw = raw
        self["match"] = None
        self["nocase"] = False
        self["rawbytes"] = False
        self["fast_pattern"] = False
        self["fast_pattern_offset"] = None
        self["fast_pattern_length"] = None
        self["offset"] = None
        self["depth"] = None
        self["distance"] = None
        self["within"] = None
        self["negated"] = False

    def __str__(self):
        return f"content:{self.raw};"

    @classmethod
    def from_string(cls, raw: str):
        content = cls(raw)
        m = cls.CONTENT_PATTERN.match(raw)
        if not m:
            raise Exception(f"Invalid content option: {raw}")

        match = m.group("match")
        content["negated"] = True if match[0] == "!" else False
        content["match"] = match[1:].strip('"') if match[0] == "!" else match.strip('"')

        if m.group("modifiers") != "":
            modifiers = [i.strip() for i in m.group("modifiers").strip().split(",")]
            for modifier in modifiers:
                if modifier in ["nocase", "rawbytes", "fast_pattern"]:
                    content[modifier] = True
                else:
                    key = modifier.split()[0]
                    value = modifier.split()[1]
                    if key not in content:
                        raise Exception(f"Invalid modifier: {modifier}. Full string is: {raw}")
                    else:
                        content[key] = value
        return content

    @property
    def ascii_matches(self) -> None or str:
        """
        Content matches can contain ASCII strings, hex bytes, or a mix of both.
        Hex bytes must be enclosed in | characters, e.g. content:"PK|03 04|";
        """
        if self["match"] is None:
            return None

        if len(self["match"].split("|")) >= 3:  # e.g. content:"MMM|03 04|XXX|05 06|NNN";
            result = ""
            match_content = self["match"].split("|")
            for i in range(0, len(match_content)):
                if i % 2 == 1:
                    result += hex2str(match_content[i])
                else:
                    result += match_content[i]
            return result
        else:
            return self["match"]

    @property
    def bytes_matches(self) -> None or bytes:
        if self["match"] is None:
            return None

        if len(self["match"].split("|")) >= 3:  # e.g. content:"MMM|03 04|XXX|05 06|NNN";
            result = b""
            match_content = self["match"].split("|")
            for i in range(0, len(match_content)):
                if i % 2 == 1:
                    result += bytes.fromhex(match_content[i])
                else:
                    result += match_content[i].encode("utf-8")
            return result
        else:
            return self["match"].encode("utf-8")


if __name__ == '__main__':
    test = r'!"Hello, this is Quagga:Bob",fast_pattern,nocase'
    content = Content.from_string(test)
    print(content.items())
    print(content.bytes_matches)
    print(len(content.ascii_matches))
    print(len(content.bytes_matches))

    test = r'content:"div|3A 3A|first-letter",nocase'
    content = Content.from_string(test)
    print(content.items())
