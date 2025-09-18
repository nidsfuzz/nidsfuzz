import random

from generation.obfs.GenericStringObfuscation import GenericStringObfuscation


class PathShifting(GenericStringObfuscation):
    # The semantics of the dict items are: { origin: [replacements] }
    INSERTION_PATTERNS = {
        repr('/'): ['//', '/./', '/~/../']
    }

    def obfuscate(self, origin: str, obfuscate_times: int = 3) -> str:
        # If there are no characters that can be modified, or the number of
        # characters to be modified is 0, return the original string directly.
        if obfuscate_times <= 0:
            return origin

        result = ''
        for char in origin:
            if repr(char) in self.INSERTION_PATTERNS:
                # determine the number of chars inserted
                obfuscate_times = random.randint(1, obfuscate_times)
                replacement = random.choices(self.INSERTION_PATTERNS[repr(char)], k=obfuscate_times)
                result += ''.join(replacement)
            else:
                result += char
        return result

if __name__ == '__main__':
    encoder = PathShifting()
    print(encoder.obfuscate('file/doc/html/rfc3986', obfuscate_times=3))