import abc
import random
from enum import Enum
from typing import Generator, List


from rule_handler import Rule
from rule_mutator.mutate_strategy.mutate_strategy import MutateStrategy
from rule_mutator.http_constructor.packet_constructor import PacketConstructor
from rule_mutator.http_constructor.buffer_constructor import BufferConstructor
from rule_handler.options import Content, Pcre, Isdataat
from rule_mutator.mutate_strategy.rule_combine_strategy import SigCombineConstructor

codec = 'latin-1'


class InsertLocation(Enum):
    START = "start"
    MIDDLE = "middle"
    END = "end"
    RANDOM = "random"


class Case(Enum):
    LOWER = "lower"
    UPPER = "upper"
    RANDOM = "random"


class RuleRandomStrategy(MutateStrategy):
    def __init__(self, proto: str = 'http', max_mutation_times: int = 5):
        super().__init__(proto=proto.lower())
        self.min_packet_size = 64
        self.max_packet_size = 1460
        self.max_mutation_times = max_mutation_times

    def mutate(self, rules: List[Rule]) -> Generator[tuple[bytes, bytes], None, None]:
        if len(rules) != 1:
            raise ValueError(
                f'[{self.__class__.__name__}]: Rule list must have exactly 1 element, but received {len(rules)}'
            )

        rule = rules[0]

        # Use later.
        # buffers: dict[str, RandomBufferConstructor] = {}
        # for buffer_name, options in rule.signature.items():
        #     buffers.setdefault(buffer_name, RandomBufferConstructor(buffer_name))
        #     if not buffers[buffer_name].push_options(options):
        #         yield None, None
        #
        # buffer_payloads: dict[str, str] = {}
        # for buffer_constructor in buffers.values():
        #     buffer_payloads[buffer_constructor.name] = buffer_constructor.payload

        # Using SigCombineConstructor here for temporary, should be replaced by other correct buffer constructor later.
        constructor = SigCombineConstructor(self._proto)
        if not constructor.add_rule_sig(rule.signature):
            yield None, None
        buffers = {buffer: constructor.get_payload(False) for buffer, constructor in constructor.buffers.items()}
        # buffers = self._generate_random_payload(rule)
        req_buffer_payloads = PacketConstructor(buffers, constructor.protocol, "REQUEST").get_buffer_payloads_http()
        res_buffer_payloads = PacketConstructor(buffers, constructor.protocol, "RESPONSE").get_buffer_payloads_http()

        # buffer payloads looks like:
        # {
        #     'http_method': 'GET',
        #     'http_space1': ' ',
        #     'http_uri': '/connecttest.txt',
        #     'http_space2': ' ',
        #     'http_version': 'HTTP/1.1',
        #     'http_crlf1': '\r\n',
        #     'http_header': 'Connection: Close\r\nUser-Agent: Microsoft NCSI\r\nHost: www.msftconnecttest.com\r\nContent-Type: text\r\nContent-Length: 52\r\n',
        #     'http_crlf2': '\r\n',
        #     'http_client_body': 'helloOworld!F6`lb{^bb.appendChild(fr.childNodes[4]);'
        # }

        mutated_req_buffer_payloads = req_buffer_payloads
        mutated_res_buffer_payloads = res_buffer_payloads
        # req_packet = PacketConstructor.concatenate(mutated_req_buffer_payloads).encode(codec)
        # res_packet = PacketConstructor.concatenate(mutated_res_buffer_payloads).encode(codec)
        # yield req_packet, res_packet
        print("request:", PacketConstructor.concatenate(mutated_req_buffer_payloads))
        print("response:", PacketConstructor.concatenate(mutated_res_buffer_payloads))
        for _ in range(self.max_mutation_times):
            mutated_request = self._apply_mutations(
                PacketConstructor.concatenate(mutated_req_buffer_payloads).encode(codec)
            )
            mutated_response = self._apply_mutations(
                PacketConstructor.concatenate(mutated_res_buffer_payloads).encode(codec)
            )
            yield mutated_request, mutated_response

    def _apply_mutations(self, packet: bytes) -> bytes:
        lines = packet.split(b'\r\n')
        mutated_lines = []
        is_body = False

        for line in lines:
            if line.strip() == b'':
                # This is the end of the HTTP headers, start mutating the request/response body
                is_body = True

            if is_body:
                # Apply mutations to the request/response body
                mutated_line = self._insert_chars(line.decode(codec)).encode(codec)
                mutated_line = self._replace_chars(mutated_line.decode(codec)).encode(codec)
                mutated_line = self._change_string_case(mutated_line.decode(codec)).encode(codec)
                mutated_lines.append(mutated_line)
            else:
                # This is an HTTP header field, skip the mutation
                mutated_lines.append(line)
        return b'\r\n'.join(mutated_lines)

    @staticmethod
    def _insert_chars(s: str, chars: str = '', where: InsertLocation = InsertLocation.RANDOM, num: int = 1) -> str:
        for _ in range(num):
            if where == InsertLocation.START:
                s = chars + s
            elif where == InsertLocation.END:
                s = s + chars
            elif where == InsertLocation.MIDDLE:
                mid = len(s) // 2
                # s = s[:mid] + chars.encode() + s[mid:]
                s = s[:mid] + chars + s[mid:]
            elif where == InsertLocation.RANDOM:
                pos = random.randint(0, len(s))
                # s = s[:pos] + chars.encode() + s[pos:]
                s = s[:pos] + chars + s[pos:]
            else:  # defined location
                pos = where
                # s = s[:pos] + chars.encode() + s[pos:]
                s = s[:pos] + chars + s[pos:]
        return s

    @staticmethod
    def _replace_chars(s: str, chars: str = '', num: int = 1) -> str:
        # TODO: the replaced value may have different length with chars.
        # TODO: set chars.
        for _ in range(num):
            if len(s) > 0:
                replace_pos = random.randint(0, len(s) - 1)
                # s = s[:replace_pos] + chars.encode() + s[replace_pos+len(chars):]
                s = s[:replace_pos] + chars + s[replace_pos + len(chars):]
        return s

    @staticmethod
    def _change_string_case(s: str, case: Case = Case.RANDOM) -> str:
        if case == Case.LOWER:
            return s.lower()
        elif case == Case.UPPER:
            return s.upper()
        else:  # RANDOM
            s = str(s)
            return ''.join(random.choice([c.lower(), c.upper()]) for c in s)

    def _generate_random_payload(self, rule: Rule) -> dict:
        mutated_payload = {}
        for buffer_name, options in rule.signature.items():
            mutated_buffer = self._generate_random_buffer(options)
            mutated_payload[buffer_name] = mutated_buffer
        return mutated_payload

    def _generate_random_buffer(self, options: List) -> str:
        content_parts = []
        isdataat_constraints = []
        current_position = 0
        for option in options:
            if isinstance(option, Content):
                content, new_position = self._apply_content_option(option, current_position)
                content_parts.append(content)
                current_position = new_position
            elif isinstance(option, Pcre):
                content = self._generate_pcre_match(option.get('match', ''))
                content_parts.append(content)
                current_position += len(content)
            elif isinstance(option, Isdataat):
                isdataat_constraints.append((option, current_position))

        base_content = ''.join(content_parts)

        packet_size = random.randint(max(self.min_packet_size, len(base_content)), self.max_packet_size)
        padding_size = packet_size - len(base_content)
        random_padding = ''.join('a' for _ in range(padding_size))

        insert_position = random.randint(0, len(random_padding))
        final_content = random_padding[:insert_position] + base_content + random_padding[insert_position:]

        for constraint, position in isdataat_constraints:
            final_content = self._apply_isdataat_constraint(final_content, constraint, position)

        return final_content

    def _apply_content_option(self, content: Content, current_position: int) -> tuple[str, int]:
        content_str = content.ascii_matches
        offset = content.get('offset')
        depth = content.get('depth')
        distance = content.get('distance')
        within = content.get('within')
        fast_pattern_offset = content.get('fast_pattern_offset')
        fast_pattern_length = content.get('fast_pattern_length')

        if offset is not None:
            current_position = max(current_position, int(offset))

        if distance is not None:
            current_position += int(distance)

        if fast_pattern_offset is not None and fast_pattern_length is not None:
            fast_pattern_offset = int(fast_pattern_offset)
            fast_pattern_length = int(fast_pattern_length)
            content_str = content_str[fast_pattern_offset:fast_pattern_offset + fast_pattern_length]

        if depth is not None:
            depth = int(depth)
            max_position = current_position + depth - len(content_str)
            insert_position = random.randint(current_position, max_position)
        elif within is not None:
            within = int(within)
            max_position = current_position + within - len(content_str)
            insert_position = random.randint(current_position, max_position)
        else:
            insert_position = current_position

        padding = ''.join(chr(random.randint(32, 126)) for _ in range(insert_position - current_position))
        result = padding + content_str
        new_position = insert_position + len(content_str)

        return result, new_position

    def _generate_pcre_match(self, pattern: str) -> str:
        return pattern

    def _apply_isdataat_constraint(self, content: str, constraint: Isdataat, current_position: int) -> str:
        location = constraint["location"]
        relative = constraint["relative"]
        negated = constraint["negated"]

        if relative:
            location += current_position

        if negated:
            if location < len(content):
                content = content[:location]
        else:
            if location >= len(content):
                padding = ''.join(chr(random.randint(32, 126)) for _ in range(location - len(content) + 1))
                content += padding

        return content


# class RandomBufferConstructor(BufferConstructor):
#
#     def __init__(self, buffer_name: str):
#         super().__init__(buffer_name)
#
#     def _push_opt_content(self, content: Content, strict: bool = True) -> bool:
#         return super()._push_opt_content(content=content, strict=strict)
#
#     def _push_opt_pcre(self, pcre: Pcre, strict: bool = True):
#         return super()._push_opt_pcre(pcre=pcre, strict=strict)
#
#     def _push_opt_isdataat(self, isdata: Isdataat, strict: bool = True):
#         return super()._push_opt_isdataat(isdata=isdata, strict=strict)
