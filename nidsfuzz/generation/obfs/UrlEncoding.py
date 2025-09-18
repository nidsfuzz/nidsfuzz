import random
import urllib.parse

from generation.obfs.GenericStringObfuscation import GenericStringObfuscation


class UrlEncoding(GenericStringObfuscation):
    RESERVED_CHARS = [
        ':',  # %3A
        '/',  # %2F
        '?',  # %3F
        '#',  # %23
        '[',  # %5B
        ']',  # %5D
        '@',  # %40
        '!',  # %21
        '$',  # %24
        '&',  # %26
        "'",  # %27
        '(',  # %28
        ')',  # %29
        '*',  # %2A
        '+',  # %2B
        ',',  # %2C
        ';',  # %3B
        '=',  # %3D
    ]

    UNSAFE_CHARS = [
        ' ',  # %20
        '"',  # %22
        '<',  # %3C
        '>',  # %3E
        '\\',  # %5C
        '^',  # %5E
        '{',  # %7B
        '}',  # %7D
        '|',  # %7C
        '%',  # %25
    ]

    CONTROL_CHARS = [chr(i) for i in range(32)] + [chr(127)]

    EXTRA_CHARS = {
        repr('~'): '%7E',
    }

    # string.ascii_letters
    # string.digits

    @property
    def encoding_dict(self) -> dict[str, str]:
        return self.EXTRA_CHARS | {repr(char): urllib.parse.quote(char, safe='') for char in
                                   self.RESERVED_CHARS + self.UNSAFE_CHARS + self.CONTROL_CHARS}

    def obfuscate(self, origin: str, obfuscate_times: int = 1) -> str:
        encoding_dict = self.encoding_dict
        interesting_chars = [index for index, char in enumerate(origin) if repr(char) in encoding_dict]
        # If there are no characters that can be replaced, or the number of
        # characters to be replaced is 0, return the original string directly.
        if not interesting_chars or obfuscate_times <= 0:
            return origin

        obfuscate_times = min(obfuscate_times, len(interesting_chars))
        interesting_chars = random.sample(interesting_chars, k=obfuscate_times)

        result = list(origin)

        for index in interesting_chars:
            origin_char = repr(result[index])
            result[index] = encoding_dict[origin_char]

        return "".join(result)


if __name__ == '__main__':
    encoder = UrlEncoding()
    print(encoder.obfuscate('asd~ll s'))
