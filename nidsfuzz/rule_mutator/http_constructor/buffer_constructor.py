import abc
import random

import exrex

import logger
from rule_handler.macro import STICKY_BUFFER
from rule_handler.options import *

codec = 'latin-1'


class BufferConstructor(abc.ABC):
    """
    This class provides the most basic option pushing methods, which are generally applicable only in
    the simplest cases, where the options in a Rule are assembled together based on their corresponding
    sticky buffers.

    "Push an option into the buffer un-strictly" means relative positioning the option into the buffer.
    """

    def __init__(self, buffer_name: str):
        if buffer_name not in STICKY_BUFFER:
            raise ValueError(f'unknown sticky buffer: {buffer_name}')

        self._name = buffer_name
        self._buffer_length = 0
        self._chunks: list[tuple[int, str]] = []
        self._padding_library = [c for c in range(ord(' '), ord('~') + 1)]  # all printable ASCII characters

    @property
    def name(self) -> str:
        return self._name

    @property
    def payload(self) -> str:
        payload = ""
        for (idx, data) in self._chunks:
            payload = payload + self._get_padding(idx - len(payload)) + data
        return payload

    def _get_padding(self, length: int) -> str:
        if length <= 0:
            return ''
        return ''.join(chr(c) for c in random.choices(self._padding_library, k=length))

    def push_options(self, options: list[Option]) -> bool:
        for option in options:
            if not self._push_option(option):
                return False
        return True

    def _push_option(self, option: Option, strict: bool = True) -> bool:
        logger.debug(f'pushing a option: {str(option)}')
        logger.debug(f'strictly follow the modifiers? {strict}')
        if isinstance(option, Content):
            return self._push_opt_content(option, strict=strict)
        elif isinstance(option, Pcre):
            return self._push_opt_pcre(option, strict=strict)
        elif isinstance(option, Isdataat):
            return self._push_opt_isdataat(option, strict=strict)
        else:
            logger.debug(f'Not supported type of option to push into buffer: {option.__class__.__name__}')
            return False

    @abc.abstractmethod
    def _push_opt_content(self, content: Content, strict: bool = True) -> bool:
        # scenario 1: negated characters should not be present in the padding library.
        if content['negated']:
            for char in content.ascii_matches:
                if ord(char) in self._padding_library:
                    self._padding_library.remove(ord(char))
            return True
        # scenario 2: the default placement strategy for the content option is relative
        elif not strict or (
                not content["offset"] and not content["depth"] and not content["distance"] and not content["within"]
        ):
            start_idx = self._buffer_length
            self._chunks.append((start_idx, content.ascii_matches))
            self._buffer_length = start_idx + len(content.ascii_matches)
            logger.debug(
                f'successfully pushed content [{content.ascii_matches.encode(codec)}] at index [{start_idx}]')
            return True
        # scenario 3: if content has relative modifiers
        elif content['distance'] or content['within']:
            start_idx = self._buffer_length + int(content["distance"] or 0)
            self._chunks.append((start_idx, content.ascii_matches))
            self._buffer_length = start_idx + len(content.ascii_matches)
            logger.debug(
                f'successfully pushed content [{content.ascii_matches.encode(codec)}] at index [{start_idx}]')
            return True
        # scenario 4: if content has absolute modifiers
        elif content['offset'] or content['depth']:
            start_idx = int(content['offset'] or 0)
            if start_idx < self._buffer_length:
                logger.error(f'option [{content}] cannot be pushed into the buffer')
                return False
            self._chunks.append((start_idx, content.ascii_matches))
            self._buffer_length = start_idx + len(content.ascii_matches)
            logger.debug(
                f'successfully pushed content [{content.ascii_matches.encode(codec)}] at index [{start_idx}]')
            return True
        return False

    @abc.abstractmethod
    def _push_opt_pcre(self, pcre: Pcre, strict: bool = True) -> bool:
        if pcre['negated']:
            return True

        try:
            logger.debug(f'generating exrex by pcre: {pcre["match"]}')
            data = exrex.getone(pcre['match'])
            logger.debug(f'generated exrex: {data}')
        except Exception as e:
            logger.error(f'{e}')
            return False

        # the default placement strategy for the pcre option is absolute
        if not strict or (strict and pcre['R']):
            start_idx = self._buffer_length
            self._chunks.append((start_idx, data))
            self._buffer_length = start_idx + len(data)
            logger.debug(
                f'successfully pushed pcre [{data.encode(codec)}] at index [{start_idx}]')
            return True
        else:
            # If some content options have been added previously,
            # it is difficult to be compatibility with the global PCRE,
            # so we agreed to position the PCRE relatively.
            # TODO: striving for a better solution
            start_idx = self._buffer_length
            self._chunks.append((start_idx, data))
            self._buffer_length = start_idx + len(data)
            logger.debug(
                f'successfully pushed pcre [{data.encode(codec)}] at index [{start_idx}]')
            return True

    @abc.abstractmethod
    def _push_opt_isdataat(self, isdata: Isdataat, strict: bool = True) -> bool:
        logger.debug(f'Not supported type of option to push into buffer: {isdata.__class__.__name__}')
        return False
