

def str2int(inp: str) -> int | None:
    try:
        num = int(inp)
    except ValueError:
        return None


def str2bool(inp: str) -> bool:

    if isinstance(inp, bool):
        return inp

    if inp.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif inp.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise ValueError(f'Boolean value expected, bot got {inp}')

def hex2str(hex_str: str) -> str:
    """
    Converts a hex string to a string of hex digits.

    @see https://tool.oschina.net/commons?type=4

    Example Usage:
    --------
    >>> result = hex2str("41 42")  # \x41 = A, \x42 = B
    >>> print(result)  # AB
    """
    res = ""
    for hex_value in hex_str.split():
        res += chr(int(hex_value, 16))
    return res

def get_ngrams(text, n):
    ngrams = set()
    for i in range(len(text) - n + 1):
        ngrams.add(text[i: i + n])
    return ngrams

def jaccard_similarity(s1, s2, n=3):
    """
    Example Usage:
    >>> s1 = "xdgfgdjlfkvirtdcvfdg"
    >>> s2 = "xdgfgdjlfkvirtdcvs243"
    >>> similarity = jaccard_similarity(s1, s2, n=3)  # 0.62

    >>> s1 = "the cat sat on the mat"
    >>> s2 = "on a mat the cat sat"
    >>> similarity = jaccard_similarity(s1, s2, n=3)  # 0.74
    """
    ngrams1 = get_ngrams(s1, n)
    ngrams2 = get_ngrams(s2, n)

    intersection_size = len(ngrams1 & ngrams2)
    union_size = len(ngrams1 | ngrams2)

    if union_size == 0:
        return 1.0

    return intersection_size / union_size




if __name__ == '__main__':
    s1 = r'"%",fast_pattern,nocase;"/^(\d{3}\x20)?\S*\x25\w/i";'
    s2 = r'"%",fast_pattern,nocase;"/\s+.*?%.*?%/ims";'
    print(jaccard_similarity(s1, s2, n=4))
