import re

from rule.options import Option


class ByteTest(Option):
    """
    The byte_test rule option tests a byte field against a specific value with a specified operator.

    byte_test is declared with four required arguments separated by commas:
        (1) number of bytes to grab from the packet.
        (2) the operator to test against the bytes in the packet.
        (3) the value to test the bytes in the packet against.
        (4) the offset of the bytes to grab.
    Note:
        * These four arguments MUST be specified in this exact order.
        * A byte_test option does not move the detection cursor.

    Format:
        byte_test:count, [!]operator, compare, offset[, relative][, endian] \
        [, string[, {dec|hex|oct}]][, dce][, bitmask bitmask];

    Example:
        byte_test:2, >, 0x7fff, 0, relative, little;

    @see https://docs.snort.org/rules/options/payload/byte_test

    Usage:
    --------
    >>> test = r'2, >, 0x7fff, 0, relative, little'
    >>> byte_test = ByteTest.from_string(test4)
    >>> print(byte_test.items())
    >>> # dict_items([('count', '2'), ('negated', False), ('operator', '>'), ('compare', '0x7fff'), ('offset', 0),
    >>> # ('relative', True), ('endian', 'little'), ('string', False), ('dec', False), ('hex', False), ('oct', False),
    >>> # ('dce', False), ('bitmask', None)])
    """

    PATTERN = re.compile(r'^'
                         r'(?P<count>[1-9]|10),\s*'
                         r'(?P<negated>!)?(?P<operator><|>|<=|>=|=|&|\^),\s*'
                         r'(?P<compare>[^,]+),\s*'
                         r'(?P<offset>[^,]+)'
                         r',?\s*(?P<relative>relative)?'
                         r',?\s*(?P<endian>big|little)?'
                         r',?\s*(?P<pick_up>(?P<string>string)?,?\s*(?P<format>dec|hex|oct)?)'
                         r',?\s*(?P<dce>dce)?'
                         r',?\s*(?P<bitmask>bitmask [^,]+)?'
                         r'$')

    def __init__(self, raw: str):
        super().__init__()
        self.raw = raw
        self["count"] = None
        self["negated"] = False
        self["operator"] = None
        self["compare"] = None
        self["offset"] = None
        self["relative"] = False
        self["endian"] = "big"
        self["string"] = False
        self["dec"] = False
        self["hex"] = False
        self["oct"] = False
        self["dce"] = False
        self["bitmask"] = None

    def __str__(self):
        return f"byte_test:{self.raw};"

    @classmethod
    def from_string(cls, raw: str):
        byte_test = cls(raw)

        m = byte_test.PATTERN.match(raw)
        if not m:
            raise Exception(f"Invalid byte_test option: {str(byte_test)}")

        byte_test["count"] = m.group("count")
        byte_test["operator"] = m.group("operator")
        byte_test["compare"] = m.group("compare")
        byte_test["offset"] = int(m.group("offset"))

        if m.group("negated") is not None:
            byte_test["negated"] = True
        if m.group("relative") is not None:
            byte_test["relative"] = True
        if m.group("endian") is not None:
            byte_test["endian"] = m.group("endian")
        if m.group("string") is not None:
            byte_test["string"] = True
        if m.group("format") is not None:
            byte_test[m.group("format")] = True
        if m.group("dce") is not None:
            byte_test["dce"] = True
        if m.group("bitmask") is not None:
            byte_test["bitmask"] = m.group("bitmask").split(" ")[-1]

        return byte_test


if __name__ == '__main__':
    test1 = r'2, >, 0x7fff, 0, relative, little'
    test2 = r'2, =, 568, 0, bitmask 0x3FF0'
    test3 = r'4, >, 1234, 0, string, dec'
    test4 = r'4, >, a_sz, 0, relative'
    test_opt = ByteTest.from_string(test1)
    print(test_opt.items())
