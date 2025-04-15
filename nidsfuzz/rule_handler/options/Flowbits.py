import re

from . import Option


class Flowbits(Option):
    """
    The flowbits rule option is used to set and test arbitrary boolean flags to track
    states throughout the entirety of a transport protocol session (UDP or TCP).

    Tracking states is done properly by creating at least two rules:
        (1) a "flowbit setter" rule that tells Snort to set a flag if the other
        conditions in it are met and
        (2) a "flowbit checker" rule to check whether that particular flag has
        been set or not set previously in the current transport protocol session,
        using that as one of its conditions.

    Format:
        flowbits:{set|unset},bit[&bit]…;
        flowbits:{isset|isnotset},bit[|bit]…;
        flowbits:{isset|isnotset},bit[&bit]…;
        flowbits:noalert;

    @see https://docs.snort.org/rules/options/non_payload/flowbits

    Usage:
    --------
    >>> test = "isset,flag1&flag2"
    >>> test_opt = Flowbits.from_string(test)
    >>> print(test_opt.items())
    >>> # dict_items([('set', None), ('unset', None), ('isset', 'flag1&flag2'), ('isnotset', None), ('noalert', False)])
    """

    SET = ["set", "setx", "unset", "toggle"]
    CHECK = ["isset", "isnotset"]

    def __init__(self, raw: str):
        super().__init__()
        self.raw = raw
        self["set"] = None
        self["unset"] = None
        self["isset"] = None
        self["isnotset"] = None
        self["noalert"] = False

    def __str__(self):
        return f"flowbits:{self.raw};"

    @classmethod
    def from_string(cls, raw: str):
        flowbit = cls(raw)

        tokens = raw.split(",", 1)
        if tokens[0] == "noalert":
            flowbit["noalert"] = True
        elif tokens[0] in flowbit and len(tokens) == 2:
            flowbit[tokens[0]] = tokens[1]
        else:
            raise Exception("Flowbit parse error on %s" % (str(flowbit)))

        return flowbit

    @property
    def checkers(self) -> set[str]:
        flowbit_names = set()
        for checker in self.CHECK:
            if self.get(checker, None) is not None:
                flowbit_names.update(re.split("[&|]", self[checker]))
        return flowbit_names

    @property
    def setters(self) -> set[str]:
        flowbit_names = set()
        for setter in self.SET:
            if self.get(setter, None) is not None:
                flowbit_names.update(re.split("&", self[setter]))
        return flowbit_names


if __name__ == '__main__':
    test = "isset,flag1&flag2"
    test_opt = Flowbits.from_string(test)
    print(test_opt.items())

