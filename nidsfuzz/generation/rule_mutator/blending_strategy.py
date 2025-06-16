import os
import random
import time
from collections import namedtuple
from typing import Generator

import exrex

from generation import logger
from generation.rule_mutator.generic_strategy import GenericStrategy
from generation.packet_render import BufferConstructor, PacketConstructor, codec

from preprocessing import Rule, RuleSet
from preprocessing.rule_parser.options import Content, Pcre, Isdataat, Option


class GenericBufferConstructor(BufferConstructor):
    PayloadElement = namedtuple("PayloadElement", ("start_index", "data"))

    def __init__(self, buffer_name: str):
        super().__init__(buffer_name)
        # Payload elements constructed from `content` and `pcre` with `R` flag.
        self.payload_element_list = []
        # Payload constructed from `pcre` with no `R` flag.
        self.payload_pcre_list = []
        # For checking `isdataat` conflict and padding, nothing to do with payload_elements and payload_pcre.
        self._payload_length_min = None
        self._payload_length_max = None
        # For signatures with `relative` modifier.
        self._previous_payload_element_end_index = 0
        # For padding, try to avoid generating `negated` `content`.
        # It can only avoid the generation of negated characters when padding.
        self._padding_character_set = [c for c in range(ord(' '), ord('~') + 1)]

    def __repr__(self):
        repr_res = f"BufferConstructor [{self._name}]:\n"
        for payload_elements in self.payload_element_list:
            repr_res += f"\t{payload_elements.start_index} {payload_elements.data.encode('latin-1')}\n"
        repr_res += f"\tpayload_length_min [{self._payload_length_min}]\n"
        repr_res += f"\tpayload_length_max [{self._payload_length_max}]\n"
        return repr_res

    def _get_available_positions(self, relative: bool = False):
        """
        Get the positions of the current buffer where there are no data yet and where subsequent data can be stored.
        """
        previous_payload_element_end = self._previous_payload_element_end_index if relative else 0
        available_positions = []
        for payload_element in self.payload_element_list:
            if payload_element.start_index - previous_payload_element_end > 0:
                pos = (previous_payload_element_end, payload_element.start_index)
                available_positions.append(pos)
            previous_payload_element_end = payload_element.start_index + len(payload_element.data)
        rear_pos = (previous_payload_element_end, -1)
        available_positions.append(rear_pos)
        return available_positions

    # TODO: consuming data is not None here.
    def _set_previous_payload_element_end_index(self, start_index: int, data: str):
        """
        Set the end index of previous payload element.
        """
        self._previous_payload_element_end_index = start_index + len(data)

    def _push_option(self, option: Option, strict: bool = True) -> bool:
        """
        Try to add one signature into current buffer.
        """
        # Sort the payload elements list for getting available positions and last position.
        self.payload_element_list = sorted(self.payload_element_list, key=lambda element: element.start_index)

        if isinstance(option, Content):
            return self._push_opt_content(option, strict=strict)
        elif isinstance(option, Pcre):
            return self._push_opt_pcre(option, strict=strict)
        elif isinstance(option, Isdataat):
            return self._push_opt_isdataat(option, strict=strict)
        else:
            # TODO: supporting other options.
            logger.debug(f"Not supported option - {type(option)}")
            return True

    def _push_opt_content(self, content: Content, strict: bool = True) -> bool:
        logger.debug(f"ContentOption found: {content}.")

        # Check `negated` modifier, `within` modifier ignored.
        if content['negated']:
            for character in content.ascii_matches:
                if ord(character) in self._padding_character_set:
                    logger.debug(f"\tDelete character [{character.encode('latin-1')}] from padding character set.")
                    self._padding_character_set.remove(ord(character))
                else:
                    logger.debug(f"\tCharacter [{character.encode('latin-1')}] not in padding character set.")
            return True

        # The first element in current buffer.
        if len(self.payload_element_list) == 0:
            logger.debug(
                f"\t[{content.ascii_matches.encode('latin-1')}] at [{content['offset'] or 0}] - First element in buffer."
            )
            self._set_previous_payload_element_end_index(int(content["offset"] or 0), content.ascii_matches)
            self.payload_element_list.append(self.PayloadElement(int(content["offset"] or 0), content.ascii_matches))
            return True

        # If no `offset`, `depth`, `distance`, and `within` modifiers, put it at last.
        if not content["offset"] and not content["depth"] and not content["distance"] and not content["within"]:
            start_index = self.payload_element_list[-1].start_index
            if self.payload_element_list[-1].data:
                start_index += len(self.payload_element_list[-1].data)
            logger.debug(f"\t[{content.ascii_matches.encode('latin-1')}] at [{start_index}] - No modifiers.")
            self._set_previous_payload_element_end_index(start_index, content.ascii_matches)
            self.payload_element_list.append(self.PayloadElement(start_index, content.ascii_matches))
            return True

        available_positions = self._get_available_positions()
        logger.debug(f"\tCurrent available positions: [{available_positions}]")
        chosen_range = None
        for position in available_positions:
            # Check `offset` and `depth` modifiers.
            # End with value -1 means no limitation.
            if content['offset'] or content['depth']:
                valid_range_start = int(content['offset'] or 0)
                valid_range_end = (valid_range_start + int(content['depth'])) if content['depth'] else -1
                logger.debug(f"\tAbsolute modifiers: [{valid_range_start}] to [{valid_range_end}]")
                overlap_range_start = max(valid_range_start, position[0])
                overlap_range_end = valid_range_end if position[1] == -1 else min(valid_range_end, position[1])
                if overlap_range_end != -1 and overlap_range_end - overlap_range_start < len(content.ascii_matches):
                    continue
                chosen_range = (overlap_range_start, overlap_range_end)
            # Check `distance` and `within` modifiers.
            if content['distance'] or content['within']:
                logger.debug(f"\tPrevious payload element end index: [{self._previous_payload_element_end_index}]")
                logger.debug(f"\tRelative modifiers: [{content['distance']}] to [{content['within']}]")
                valid_range_start = self._previous_payload_element_end_index + int(content['distance'] or 0)
                valid_range_end = (valid_range_start + int(content['within'])) if content['within'] else -1
                logger.debug(f"\tAbsolute modifiers: [{valid_range_start}] to [{valid_range_end}]")
                if chosen_range:
                    overlap_range_start = max(valid_range_start, chosen_range[0])
                    overlap_range_end = valid_range_end if chosen_range[1] == -1 else min(
                        valid_range_end,
                        chosen_range[1]
                    )
                else:
                    overlap_range_start = max(valid_range_start, position[0])
                    overlap_range_end = valid_range_end if position[1] == -1 else min(valid_range_end, position[1])
                if overlap_range_end != -1 and overlap_range_end - overlap_range_start < len(content.ascii_matches):
                    logger.debug(f"\tNot suitable: [{position[0]}] to [{position[1]}].")
                    continue
                chosen_range = (overlap_range_start, overlap_range_end)
        if chosen_range:
            logger.debug(f"\t[{content.ascii_matches.encode('latin-1')}] at [{chosen_range[0]}].")
            self._set_previous_payload_element_end_index(chosen_range[0], content.ascii_matches)
            self.payload_element_list.append(self.PayloadElement(chosen_range[0], content.ascii_matches))
            return True
        else:
            logger.debug(f"\tAdd signature failed: no suitable position.")
            return False

    def _push_opt_pcre(self, pcre: Pcre, strict: bool = True):
        logger.debug(f"PcreOption found: {pcre}.")

        # TODO: check the `negated` modifier more carefully.
        if pcre['negated']:
            logger.debug(f"\tSkip signature - Negated.")
            return True

        try:
            data = exrex.getone(pcre['match'])
        except:
            logger.debug(f"\tGenerating data from regex failed [{pcre['match']}].")
            return True

        if pcre['R']:
            # If `R` flag exists, put it at last.
            start_index = self._previous_payload_element_end_index
            logger.debug(f"\t[{data.encode('latin-1')}] at [{start_index}] - Pcre with `R`.")
            self._set_previous_payload_element_end_index(self._previous_payload_element_end_index, data)
            self.payload_element_list.append(self.PayloadElement(start_index, data))
        else:
            # If `R` flag not exists, it is a global pcre, append it to pcre list.
            logger.debug(f"\t[{data.encode('latin-1')}] - Pcre without `R`.")
            self.payload_pcre_list.append(data)
            # For better satisfy the rule, also put it at last.
            start_index = self._previous_payload_element_end_index
            logger.debug(f"\t[{data.encode('latin-1')}] at [{start_index}] - Pcre without `R`.")
            self._set_previous_payload_element_end_index(self._previous_payload_element_end_index, data)
            self.payload_element_list.append(self.PayloadElement(start_index, data))
        return True

    def _push_opt_isdataat(self, isdata: Isdataat, strict: bool = True):
        logger.debug(f"IsdataatOption found: {isdata}.")
        if isdata['negated']:
            payload_length_max = isdata['location'] + self._previous_payload_element_end_index if isdata[
                'relative'] else 0
            if self._payload_length_min is None or self._payload_length_min <= payload_length_max:
                self._payload_length_max = payload_length_max
                logger.debug(f"\tAdd signature succeed: payload_length_max to [{payload_length_max}].")
                return True
            else:
                logger.debug(
                    f"\tAdd signature failed: payload_length_max conflicts with payload_length_min "
                    f"[{self._payload_length_min}]."
                )
                return False
        else:
            # isdataat:0 checks that there is at least one byte present after the current cursor location.
            payload_length_min = 1 + isdata['location'] + self._previous_payload_element_end_index if isdata[
                'relative'] else 0
            if self._payload_length_min is not None and payload_length_min <= self._payload_length_min:
                logger.debug(f"\tAdd signature succeed: payload_length_min [{payload_length_min}] ignored.")
                return True
            elif self._payload_length_max is None or self._payload_length_max >= payload_length_min:
                self._payload_length_min = payload_length_min
                logger.debug(f"\tAdd signature succeed: payload_length_min to [{payload_length_min}].")
                return True
            else:
                logger.debug(
                    f"\tAdd signature failed: payload_length_min conflicts with payload_length_max "
                    f"[{self._payload_length_max}]."
                )
                return False

    def _get_padding(self, padding_length: int) -> str:
        """
        Get a padding string of length `padding_length` that does not contain negated characters.
        """
        padding = ""
        for _ in range(padding_length):
            if len(self._padding_character_set) == 0:
                padding += chr(random.choice(range(ord(' '), ord('~') + 1)))
            else:
                padding += chr(random.choice(self._padding_character_set))
        return padding

    def get_payload(self, from_pcre=False, force_pcre=False) -> str:
        """
        Get current buffer constructed from payload elements with padding or global pcre.
        """
        # If from_pcre is set and payload_pcre_list is not empty, use global pcre.
        if from_pcre and (len(self.payload_pcre_list) != 0 or force_pcre):
            return "".join(self.payload_pcre_list)

        # Otherwise use payload elements with padding.
        payload = ""
        for payload_element in self.payload_element_list:
            if len(payload) < payload_element.start_index:
                payload += self._get_padding(payload_element.start_index - len(payload))
            payload += payload_element.data

        if self._payload_length_min and self._payload_length_max:
            if len(payload) < self._payload_length_min:
                logger.debug(f"Padding payload. [{len(payload)}] to [{self._payload_length_min}]")
                payload += self._get_padding(
                    random.randint(self._payload_length_min, self._payload_length_max) - len(payload)
                )
            elif len(payload) > self._payload_length_max:
                logger.debug(f"Payload too long. [{len(payload)}] to [{self._payload_length_max}]")
        elif self._payload_length_min:
            if len(payload) < self._payload_length_min:
                logger.debug(f"Padding payload. [{len(payload)}] to [{self._payload_length_min}]")
                payload += self._get_padding(self._payload_length_min - len(payload))
        elif self._payload_length_max:
            if len(payload) > self._payload_length_max:
                logger.debug(f"Payload too long. [{len(payload)}] to [{self._payload_length_max}]")

        return payload


class SigCombineConstructor:
    def __init__(self, protocol: str):
        self.buffers = {}
        self.protocol = protocol.upper()

    def __repr__(self):
        repr_res = f"== SigCombineConstructor ==\n"
        for buffer, buffer_constructor in self.buffers.items():
            repr_res += f"{repr(buffer_constructor)}"
        repr_res += f"== SigCombineConstructor ==\n"
        return repr_res

    def add_rule_sig(self, rule_sig: dict[str, list[Option]]) -> bool:
        """
        Try to add all signatures of a rule to some combined signatures according to buffer.
        """
        # TODO: backup if failed

        # Remove content options contained by pcre options without `R` flag.
        filtered_buffer_options = []
        for buffer, options in rule_sig.items():
            option_stack = []
            for option in options:
                if isinstance(option, Pcre) and not option['R'] and option['match'] is not None:
                    while len(option_stack) != 0 and isinstance(option_stack[-1], Content):
                        # TODO: content['match'] may have different expression with pcre['match']
                        if option_stack[-1]['match'] is not None and option_stack[-1]['match'] in option['match']:
                            print(f"Content removed: [{option_stack[-1]['match']}] in [{option['match']}]")
                            option_stack.pop()
                        else:
                            break
                option_stack.append(option)
            filtered_buffer_options.append((buffer, option_stack))

        for buffer, options in filtered_buffer_options:
            self.buffers.setdefault(buffer, GenericBufferConstructor(buffer))
            if not self.buffers[buffer].push_options(options):
                return False
        return True

        # for buffer, options in rule_sig.items():
        #     self.buffers.setdefault(buffer, GenericBufferConstructor(buffer))
        #     if not self.buffers[buffer].push_options(options):
        #         return False
        # return True

    # TODO: construct the payload according to the sticky_buffer ordering in different protocols.
    # TODO: payload_pcre not used currently.
    def get_packet(self, from_pcre: bool, packet_type: str = "") -> str:
        """
        Get current package constructed from buffers which contains combined signatures.
        """
        if self.protocol == "HTTP":
            return self._get_packet_http(from_pcre, packet_type)
        else:
            payload = ""
            for _, buffer_constructor in self.buffers.items():
                payload += buffer_constructor.get_payload(from_pcre)
            return payload

    def _get_packet_http(self, from_pcre: bool, packet_type: str) -> str:
        buffers = {buffer: constructor.get_payload(from_pcre) for buffer, constructor in self.buffers.items()}
        packet_constructor = PacketConstructor(buffers, self.protocol, packet_type)
        return packet_constructor.get_packet()

    def _get_buffer(self):
        return self.buffers.keys()


class BlendingStrategy(GenericStrategy):

    def mutate(self, rules: list[Rule]) -> Generator[tuple[bytes, bytes], None, None]:
        constructor = SigCombineConstructor(self.proto)
        current_combination_result = True
        for rule in rules:
            if not constructor.add_rule_sig(rule.signature):
                current_combination_result = False
                break
        if current_combination_result:
            request_packet_pcre = constructor.get_packet(True, "REQUEST")
            response_packet_pcre = constructor.get_packet(True, "RESPONSE")
            request_packet = constructor.get_packet(False, "REQUEST")
            response_packet = constructor.get_packet(False, "RESPONSE")
            # yield request_packet_pcre.encode("latin-1"), response_packet_pcre.encode("latin-1")
            yield request_packet.encode("latin-1"), response_packet.encode("latin-1")
        else:
            yield b"", b""


def test_blending(rule_file_path: str, protocol: str):
    rule_file_processor = RuleSet.from_file(rule_file_path)
    rules = rule_file_processor.rules

    # Test combination of 1 rule.
    total_num = 0
    success_num = 0
    failure_num = 0
    for rule in rules:
        total_num += 1
        sig_combine_constructor = SigCombineConstructor(protocol)
        rule_signature = rule.signature
        if sig_combine_constructor.add_rule_sig(rule_signature) is True:
            success_num += 1
            request_packet = sig_combine_constructor.get_packet(False, "REQUEST")
            response_packet = sig_combine_constructor.get_packet(False, "RESPONSE")
            # yield request_packet_pcre.encode("latin-1"), response_packet_pcre.encode("latin-1")
            print(request_packet.encode("latin-1"))
            print(response_packet.encode("latin-1"))
        else:
            failure_num += 1
    print(f"== Test result for combination of 1 rule in {os.path.basename(rule_file_path)}. ==")
    print(f"success : {success_num}, {success_num / total_num * 100}%")
    print(f"failure : {failure_num}, {failure_num / total_num * 100}%")
    print(f"total   : {total_num}")
    time.sleep(0.2)


if __name__ == "__main__":
    from pathlib import Path
    rule_file = Path(__file__).parent.parent.parent.parent / "resources" / "rules" / "snort3-browser-chrome.rules"

    test_blending(f'{rule_file}', "HTTP")
