from collections.abc import Sequence


class UserBytes(Sequence):

    def __init__(self, data: bytes = None):
        if data is None:
            self.data = b''
        elif isinstance(data, bytes):
            self.data = data
        else:
            self.data = bytes(data)

    def __getitem__(self, index):
        # The slice operation returns a new UserBytes instance
        if isinstance(index, slice):
            return self.__class__(self.data[index])
        # The indexing operation returns an integer
        return self.data[index]

    def __len__(self):
        return len(self.data)

    def __repr__(self):
        return f'{self.__class__.__name__}({self.data!r})'

    def __str__(self):
        return repr(self.data)

    def __eq__(self, other):
        if isinstance(other, UserBytes):
            return self.data == other.data
        if isinstance(other, bytes):
            return self.data == other
        return NotImplemented

    def __hash__(self):
        return hash(self.data)

    def __add__(self, other):
        if isinstance(other, (UserBytes, bytes)):
            return self.__class__(self.data + bytes(other))
        return NotImplemented

    def __getattr__(self, item):
        # Get the same-named attribute (or method) from the internal bytes object.
        attr = getattr(self.data, item)
        # If the attribute is callable (e.g., .hex(), .decode()), call it and returns the result.
        if callable(attr):
            # Returns a new function that...
            def wrapper(*args, **kwargs):
                # ...calls methods on the original bytes object...
                result = attr(*args, **kwargs)
                # ...if the result is bytes, wraps it in our own class and returns it...
                if isinstance(result, bytes):
                    return self.__class__(result)
                # ...otherwise, returns the result directly (e.g., int, bool, str, etc.)
                return result
            # ...
            return wrapper
        # If the attribute is not a method (just a value), returns directly
        return attr


if __name__ == '__main__':
    ub = UserBytes(b'\xda\x4c\x81\x80\x00\x01')
    print(f'instance object: {ub!r}')
    print(f'instance type: {type(ub)}')

    ub_upper = ub.upper()
    print(f'instance upper: {ub_upper!r}')
    print(f'instance upper type: {type(ub_upper)}')

    print(f'length: {len(ub)}')
    print(f'the value of the second byte: {ub[1]}')
    print(f'slice from 2 to 5: {ub[1:4]!r} ')

    ub_bew = ub + b'\xff\xee'
    print(f'instance splicing: {ub_bew!r}')
    print(f'instance splicing type: {type(ub_bew)}')