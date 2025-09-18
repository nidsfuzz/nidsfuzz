import abc
import math
import random
from typing import Generator

import exrex

from logger import logger
from generation.UserBytes import UserBytes
from generation.grammars import load_grammar
from rule import StickyBuffer, Proto, ProtoType, Option, Content, Pcre, Isdataat, ByteTest, RuleSet, Rule


class DataChunk(UserBytes):

    def __init__(self, index: int, data: bytes):
        super().__init__(data=data)

        self.index = index


class PassThroughSignatureRender:

    def __init__(self, sticky_buffer: str, proto: str):
        if sticky_buffer not in StickyBuffer.all():
            raise ValueError(f"Unsupported sticky buffer: {sticky_buffer}")
        if proto.lower() not in Proto.all():
            raise ValueError(f"Unsupported protocol: {proto}")

        self.proto = Proto.lookup(proto.lower())

        if self.proto.type == ProtoType.TEXT:
            # all printable characters [32-126], and part of control characters [10, 13, 9]
            self.padding_library: list[int] = [char for char in range(ord(' '), ord('~') + 1)] + [ord('\n'), ord('\r'),
                                                                                                  ord('\t')]
        elif self.proto.type == ProtoType.BIN:
            self.padding_library: list[int] = list(range(256))  # 0 - 255
        else:
            raise ValueError(f"Unsupported protocol: {proto}")

        self.sticky_buffer: str = sticky_buffer
        self.min_length: int = 0
        self.max_length: int = math.inf
        self.data_chunks: list[DataChunk] = []
        self.global_pcre_data: list[bytes] = []
        self.preceding_data_chunk_end_index = 0

    def generate_padding(self, padding_length: int) -> bytes:
        padding = b""
        if padding_length <= 0:
            return padding
        else:
            if len(self.padding_library) == 0:
                padding = bytes(random.choices([char for char in range(ord(' '), ord('~') + 1)], k=padding_length))
            else:
                padding = bytes(random.choices(self.padding_library, k=padding_length))
        return padding

    def orchestrate(self, rule_options: list[Option]) -> bool:
        for option in rule_options:
            logger.debug(f'pushing a option: {option}')
            if isinstance(option, Content):
                if not self.push_content(option):
                    return False
            elif isinstance(option, Pcre):
                if not self.push_pcre(option):
                    return False
            elif isinstance(option, Isdataat):
                if not self.push_isdataat(option):
                    return False
            elif isinstance(option, ByteTest):
                if not self.push_bytetest(option):
                    return False
            else:
                logger.debug(f'Unsupported type of options: {option.__class__.__name__}')
                return False
        return True

    def render(self, only_global_pcre: bool = False) -> bytes:
        if only_global_pcre and len(self.global_pcre_data) != 0:
            return b"".join(self.global_pcre_data)

        result = b""
        for data_chunk in self.data_chunks:
            index, data = data_chunk.index, data_chunk.data
            result = result + self.generate_padding(index - len(result)) + data

        if self.max_length == math.inf:
            if len(result) < self.min_length:
                result += self.generate_padding(self.min_length - len(result))
        else:
            if len(result) < self.min_length:
                result += self.generate_padding(random.randint(self.min_length, self.max_length) - len(result))
            if len(result) > self.max_length:
                logger.warning(
                    f"The rendered value [{len(result)}] exceeds the maximum allowed length of [{self.max_length}].]")

        return result

    def push_content(self, content: Content) -> bool:
        data = content.bytes_matches
        # scenario 1: negated characters should not be present in the padding library.
        if content['negated']:
            for byte in data:
                if byte in self.padding_library:
                    self.padding_library.remove(byte)
            return True
        # scenario 2: the default placement strategy for the content option is relative
        elif not content["offset"] and not content["depth"] and not content["distance"] and not content["within"]:
            start_idx = self.preceding_data_chunk_end_index
            self.data_chunks.append(DataChunk(start_idx, data))
            self.preceding_data_chunk_end_index = start_idx + len(data)
            return True
        # scenario 3: if content has relative modifiers
        elif content['distance'] or content['within']:
            start_idx = self.preceding_data_chunk_end_index + int(content["distance"] or 0)
            self.data_chunks.append(DataChunk(start_idx, data))
            self.preceding_data_chunk_end_index = start_idx + len(data)
            return True
        # scenario 4: if content has absolute modifiers
        elif content['offset'] or content['depth']:
            start_idx = int(content['offset'] or 0)
            if start_idx < self.preceding_data_chunk_end_index:
                # logger.error(f'The content option cannot be pushed into the buffer: {content}')
                return False
            self.data_chunks.append(DataChunk(start_idx, data))
            self.preceding_data_chunk_end_index = start_idx + len(data)
            return True
        return False

    def push_pcre(self, pcre: Pcre) -> bool:
        try:
            data = exrex.getone(pcre['match']).encode("utf-8")
        except Exception as e:
            logger.error(f'{e}')
            return False

        if pcre['negated']:
            return True
        # the default placement strategy for the pcre option is absolute
        elif pcre['R']:
            start_idx = self.preceding_data_chunk_end_index
            self.data_chunks.append(DataChunk(start_idx, data))
            self.preceding_data_chunk_end_index = start_idx + len(data)
            return True
        else:
            # If some content options have been added previously,
            # it is difficult to be compatibility with the global PCRE,
            # so we agreed to position the PCRE relatively.
            # TODO: striving for a better solution
            start_idx = self.preceding_data_chunk_end_index
            self.data_chunks.append(DataChunk(start_idx, data))
            self.preceding_data_chunk_end_index = start_idx + len(data)
            return True

    def push_isdataat(self, isdataat: Isdataat) -> bool:
        if isdataat['negated']:
            start_idx = self.preceding_data_chunk_end_index if isdataat['relative'] else 0
            allowed_max_length = isdataat['location'] + start_idx
            if self.min_length <= allowed_max_length <= self.max_length:
                logger.debug(f"\tAdd signature succeed: max_length to [{allowed_max_length}].")
                self.max_length = allowed_max_length
                return True
            else:
                logger.debug(
                    f"\tAdd signature failed: min_length [{self.min_length}] or max_length [{self.max_length}] "
                    f"conflicts with allowed_max_length [{allowed_max_length}]."
                )
                return False
        else:
            # isdataat:0 checks that there is at least one byte present after the current cursor location.
            start_idx = self.preceding_data_chunk_end_index if isdataat['relative'] else 0
            allowed_min_length = 1 + isdataat['location'] + start_idx
            if self.min_length <= allowed_min_length <= self.max_length:
                logger.debug(f"\tAdd signature succeed: min_length to [{allowed_min_length}].")
                self.min_length = allowed_min_length
                return True
            else:
                logger.debug(
                    f"\tAdd signature failed: min_length [{self.min_length}] or max_length [{self.max_length}] "
                    f"conflicts with allowed_min_length [{allowed_min_length}]."
                )
                return False

    def push_bytetest(self, bytetest: ByteTest) -> bool:
        # Step 1: Orchestrate the length limit
        start_idx = (self.preceding_data_chunk_end_index if bytetest['relative'] else 0) + int(bytetest['offset'] or 0)
        allowed_min_length = start_idx + int(bytetest['count'] or 0)
        if self.min_length <= allowed_min_length <= self.max_length:
            self.min_length = allowed_min_length
        else:
            return False
        return True

class PassThroughMutator:

    def __init__(self, ruleset: RuleSet):
        self.rule_pool = ruleset

        logger.info(f'Pass-through mutator initialized.')

    def generate(self, *rules: Rule, proto: str) -> Generator[tuple[bytes, bytes], None, str]:
        # Step 1: Check whether the received rules meet the requirements
        if not self.is_valid(*rules, proto=proto):
            return "Rules check failed."

        # Step 2: Generate prerequisite packets to bring the connection into the desired state.
        ruleset = RuleSet.from_rules(list(rules))
        invalid_flowbits = ruleset._check_flowbits.keys() - self.rule_pool._set_flowbits.keys()
        if invalid_flowbits:
            logger.warning(f'Trying to use rules with invalid flowbits for generation: {invalid_flowbits}')
            return f'Trying to use rules with invalid flowbits for generation: {invalid_flowbits}'

        for flowbit, _ in ruleset._check_flowbits.items():
            prerequisite_rule = self.rule_pool._set_flowbits[flowbit][0]
            pass_through = PassThroughMutator(ruleset=self.rule_pool)
            yield from pass_through.generate(prerequisite_rule, proto=proto)

        # Step 3: Extract the rule options and filter out redundant options
        signatures: dict[str, list[Option]] = self.mutate_signatures(*rules)

        # Step 4: Orchestrate the limits defined in the signatures
        buffer_renders: dict[str, PassThroughSignatureRender] = {}
        for buffer, options in signatures.items():
            logger.debug(f'Orchestrating limits for buffer: {buffer}')
            buffer_render = buffer_renders.setdefault(buffer, self.render_signatures(sticky_buffer=buffer,
                                                                                     proto=proto))
            if not buffer_render.orchestrate(options):
                logger.debug(f"Failed to orchestrate rules: {[rule.id for rule in rules]}")
                return 'Orchestration failed.'

        # Step 5: Generate the bidirectional test packets
        grammar = load_grammar(proto)
        part_fields = {buffer: render.render() for buffer, render in buffer_renders.items()}
        grammar.populate(part_fields)
        yield grammar.generate(pkt_type='REQUEST'), grammar.generate(pkt_type='RESPONSE')

        return "Generation normally finished."

    @staticmethod
    def eliminate_redundant_options(options: list[Option]) -> list[Option]:
        result = []

        def add_option(existing_options: list[Option], new_option: Option):
            if not (isinstance(new_option, Pcre) and not new_option['R'] and new_option['match'] is not None):
                existing_options.append(new_option)
                return

            if not existing_options:
                existing_options.append(new_option)
                return

            preceding_option = existing_options[-1]
            if isinstance(preceding_option, Content) and preceding_option['match'] is not None and preceding_option[
                'match'] in new_option['match']:
                removed_option = existing_options.pop()
                logger.debug(f"Eliminate a redundant option: {removed_option}")
                add_option(existing_options, new_option)
            else:
                existing_options.append(new_option)

        for option in options:
            add_option(result, option)
        return result

    # TODO: Subclass should override this method.
    def mutate_signatures(self, *rules: Rule) -> dict[str, list[Option]]:
        signatures = {}
        for rule in rules:
            for buffer, options in rule.signature.items():
                options = self.eliminate_redundant_options(options)
                signatures.setdefault(buffer, []).extend(options)
        return signatures

    # TODO: Subclass should override this method.
    def is_valid(self, *rules: Rule, proto: str) -> bool:
        if len(rules) != 1:
            logger.warning(f'Expected 1 rule, got {len(rules)}')
            return False

        if proto.lower() not in Proto.all():
            raise ValueError(f"Unsupported protocol: {proto}")

        return True

    # TODO: Subclass should override this method.
    def render_signatures(self, sticky_buffer, proto) -> PassThroughSignatureRender:
        return PassThroughSignatureRender(sticky_buffer, proto)