import abc
import copy
import random
import urllib.parse
from typing import Generator

import logger
from rule_handler.options import *
from rule_mutator.mutate_strategy.mutate_strategy import MutateStrategy
from rule_mutator.http_constructor.packet_constructor import PacketConstructor
from rule_mutator.http_constructor.buffer_constructor import BufferConstructor, codec
from rule_handler import Rule


class RuleObfuscateStrategy(MutateStrategy):
    """
    Under this strategy, it simulates the attack of obfuscation via performing two operations
    to mutate the signatures:
        (i) Replace specific characters with encoded ones.
        (ii) Insert given characters in particular positions.
    """

    def __init__(self, max_replace_time: int = 1, max_insert_time: int = 3, proto: str = 'http'):
        super().__init__(proto=proto)
        self.max_replace_time = max_replace_time
        # MaxLoopTime specified by user to limit the maximum times of obfuscation
        self.max_insert_time = max_insert_time

    def mutate(self, rules: list[Rule]) -> Generator[tuple[bytes, bytes], None, None]:
        if len(rules) != 1:
            raise ValueError(f'[{self.__class__.__name__}]: Rule list must have exactly 1 element, but received  {len(rules)}')

        replace_time = random.randint(1, self.max_replace_time)
        insert_time = random.randint(1, self.max_insert_time)

        yield self._replace_obfuscation(rules[0], replace_time)
        yield self._insert_obfuscation(rules[0], insert_time)


    def _replace_obfuscation(self, rule: Rule, obfuscate_time) -> tuple[bytes, bytes]:
        buffers = []
        for buffer_name, options in rule.signature.items():
            buffers.append(Replace(buffer_name=buffer_name, replace_time=obfuscate_time, options=options))
        return self._generate(buffers)

    def _insert_obfuscation(self, rule: Rule, obfuscate_time) -> tuple[bytes, bytes]:
        buffers = []
        for buffer_name, options in rule.signature.items():
            buffers.append(Insert(buffer_name=buffer_name, insert_time=obfuscate_time, options=options))
        return self._generate(buffers)

    def _generate(self, buffers: list[BufferConstructor]):
        res: dict[str, str] = {}
        for buffer in buffers:
            res[buffer.name] = buffer.payload

        return (
            PacketConstructor(res, self._proto, 'REQUEST').get_packet().encode(codec),
            PacketConstructor(res, self._proto, 'RESPONSE').get_packet().encode(codec),
        )


class GenericObfuscation(BufferConstructor):

    def __init__(self, buffer_name: str, obf_time: int):
        super().__init__(buffer_name)

        if obf_time < 1:
            raise ValueError(f'[{self.__class__.__name__}]: Obfuscation time must be greater than or equal to 1')
        self._obf_time = obf_time


    def _push_opt_content(self, content: Content, strict: bool = True) -> bool:
        if content['negated']:
            return super()._push_opt_content(content=content, strict=strict)

        obfuscated_content = copy.deepcopy(content)
        obfuscated_content['match'] = self.obfuscate(content.ascii_matches)

        if super()._push_opt_content(content=obfuscated_content, strict=strict):
            return True

        if strict and (obfuscated_content['offset'] or obfuscated_content['depth']):
            start_idx = int(obfuscated_content['offset'] or 0)
            # increase the offset by the corresponding value to skip repeated options
            start_idx = self._skip_repeated_options(offset=start_idx)
            if start_idx < self._buffer_length:
                logger.error(f'option [{obfuscated_content}] cannot be pushed into the buffer')
                return False
            self._chunks.append((start_idx, obfuscated_content.ascii_matches))
            self._buffer_length = start_idx + len(obfuscated_content.ascii_matches)
            logger.debug(
                f'successfully pushed content [{obfuscated_content.ascii_matches.encode(codec)}] at index [{start_idx}]')
            return True

    def _push_opt_pcre(self, pcre: Pcre, strict: bool = True):
        if pcre['negated']:
            return super()._push_opt_pcre(pcre=pcre, strict=strict)

        obfuscated_pcre = copy.deepcopy(pcre)
        obfuscated_pcre['match'] = self.obfuscate(pcre['match'])

        return super()._push_opt_pcre(pcre=obfuscated_pcre, strict=strict)


    def _push_opt_isdataat(self, isdata: Isdataat, strict: bool = True):
        return super()._push_opt_isdataat(isdata=isdata, strict=strict)

    def _skip_repeated_options(self, offset: int) -> int:
        """
        For content/pcre options, if there are obfuscated options preceding it,
        the offset value must be increased to skip over those obfuscated characters.
        """
        pre_opt_num = len(self._chunks)
        return offset + pre_opt_num * self._obf_time

    @property
    @abc.abstractmethod
    def obfuscated_chars(self) -> set[str]:
        pass

    @abc.abstractmethod
    def obfuscate(self, origin: str) -> str:
        pass


class Replace(GenericObfuscation):
    """
    This operation randomly picks up spaces and underlines in signatures, and then replaces
    them with encoded characters in generated strings.

    According to RFC 3986, percent encoding is used to represent certain reserved characters,
    invisible characters (such as spaces), and characters that cannot be directly included in URLs.

    @see https://datatracker.ietf.org/doc/html/rfc3986
    """

    _reserved_chars = [
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

    _unsafe_chars = [
        ' ',  # %20
        '"',  # %22
        '<',  # %3C
        '>',  # %3E
        '\\', # %5C
        '^',  # %5E
        '{',  # %7B
        '}',  # %7D
        '|',  # %7C
        '%',  # %25
    ]

    _control_chars = [chr(i) for i in range(32)] + [chr(127)]

    _extra_chars = {
        '~': '%7E',
    }

    encoded_chars = {repr(char): urllib.parse.quote(char, safe='') for char in
                     _reserved_chars + _unsafe_chars + _control_chars} | _extra_chars

    def __init__(
            self,
            buffer_name: str,
            replace_time: int = 1,
            options: list[Option] = None,
            obfuscated_chars: set[str] = None
    ):
        super().__init__(buffer_name=buffer_name, obf_time=replace_time)

        logger.debug(f'creating a replacement obfuscation with replace_time: {self._obf_time}')

        self._obfuscated_chars = obfuscated_chars if obfuscated_chars is not None else set()
        for char in [repr(char) for char in [' ', '_']]:
            self._obfuscated_chars.add(char)

        if options is not None:
            self.push_options(options=options)

    @property
    def obfuscated_chars(self) -> set[str]:
        return self._obfuscated_chars

    def obfuscate(self, origin: str) -> str:

        logger.debug(f'applying the replacement obfuscation to: {origin}')

        obfuscated = ''
        for char in origin:
            if repr(char) in self.obfuscated_chars:
                replaced_chars = []
                replaced_encoded_chars = ''
                for repr_char, encoded_char in random.choices(list(self.encoded_chars.items()), k=self._obf_time):
                    replaced_chars.append(repr_char)
                    replaced_encoded_chars += encoded_char
                obfuscated += replaced_encoded_chars
                logger.debug(f'replaced {repr(char)} with {replaced_chars}, encoded format: {replaced_encoded_chars}')
            else:
                obfuscated += char

        logger.debug(f'obfuscated result: {obfuscated}')

        return obfuscated


class Insert(GenericObfuscation):
    """
    Insertion only occurs before or after special characters instead of in between letters.

    Currently, only one insertion pattern is supported:
        (1) inserting an arbitrary number of "./" or "/." either before or after the character "/".
    """

    # TODO: add more insertion patterns
    # entry format is { trigger: [before, after] }
    inserted_chars = {
        repr('/'): ['/.', './']
    }

    def __init__(
            self,
            buffer_name: str,
            insert_time: int = 2,
            options: list[Option] = None,
            obfuscated_chars: set[str] = None
    ):
        super().__init__(buffer_name=buffer_name, obf_time=insert_time)

        logger.debug(f'creating a insertion obfuscation with insert_time: {self._obf_time}')

        self._obfuscated_chars = obfuscated_chars if obfuscated_chars is not None else set()
        for char, _ in self.inserted_chars.items():
            self._obfuscated_chars.add(char)

        if options is not None:
            self.push_options(options=options)

    @property
    def obfuscated_chars(self) -> set[str]:
        return self._obfuscated_chars


    def obfuscate(self, origin: str) -> str:

        logger.debug(f'applying the insertion obfuscation to: {origin}')

        obfuscated = ''
        for char in origin:
            if repr(char) in self.obfuscated_chars:
                # determine where to insert characters
                before, after = random.sample([True, True, False], k=2)

                # before the obfuscated character
                if before:
                    inserted_chars = self.inserted_chars[repr(char)][0]
                    for encoded_chars in random.choices(self.inserted_chars[repr(char)], k=self._obf_time - 1):
                        inserted_chars += encoded_chars
                    obfuscated += inserted_chars
                # keep the obfuscated character
                obfuscated += char
                # after the obfuscated character
                if after:
                    inserted_chars = ''
                    for encoded_chars in random.choices(self.inserted_chars[repr(char)], k=self._obf_time - 1):
                        inserted_chars += encoded_chars
                    obfuscated = obfuscated + inserted_chars + self.inserted_chars[repr(char)][1]
            else:
                obfuscated += char

        logger.debug(f'obfuscated result: {obfuscated}')

        return obfuscated
