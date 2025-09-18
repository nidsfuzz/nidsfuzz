import exrex

from logger import logger
from generation.PassThroughMutator import PassThroughSignatureRender, DataChunk, PassThroughMutator
from rule import ByteTest, Content, Pcre, Isdataat, RuleSet, Rule, Option


class BlendingSignatureRender(PassThroughSignatureRender):

    def push_bytetest(self, bytetest: ByteTest) -> bool:
        return super().push_bytetest(bytetest)

    def query_available_positions(self, relative: bool = False) -> list[tuple[int, int]]:
        """
        Gets the position where there is no data yet and subsequent data can be stored.
        """
        available_positions = []
        start_position = self.preceding_data_chunk_end_index if relative else 0
        for data_chunk in self.data_chunks:
            index, data = data_chunk.index, data_chunk.data
            if index > start_position:
                pos = (start_position, index)
                available_positions.append(pos)
            start_position = index + len(data)
        rear_pos = (start_position, -1)
        available_positions.append(rear_pos)
        return available_positions

    def push_content(self, content: Content) -> bool:
        data = content.bytes_matches

        # Check `negated` modifier, `within` modifier ignored.
        if content['negated']:
            for byte in data:
                if byte in self.padding_library:
                    logger.debug(f"\tDelete character [{byte}] from padding library.")
                    self.padding_library.remove(byte)
            return True
        # The first data chunk in the current buffer.
        elif len(self.data_chunks) == 0:
            logger.debug(f"\t[{data}] at [{content['offset'] or 0}] - First element in buffer.")
            start_idx = int(content["offset"] or 0)
            self.preceding_data_chunk_end_index = start_idx + len(data)
            self.data_chunks.append(DataChunk(start_idx, data))
            return True
        # If no `offset`, `depth`, `distance`, and `within` modifiers, put it at last.
        elif not content["offset"] and not content["depth"] and not content["distance"] and not content["within"]:
            start_idx = self.data_chunks[-1].index
            if self.data_chunks[-1].data:
                start_idx += len(self.data_chunks[-1].data)
            logger.debug(f"\t[{data}] at [{start_idx}] - No modifiers.")
            self.preceding_data_chunk_end_index = start_idx + len(data)
            self.data_chunks.append(DataChunk(start_idx, data))
            return True

        available_positions = self.query_available_positions()
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
                if overlap_range_end != -1 and overlap_range_end - overlap_range_start < len(data):
                    continue
                chosen_range = (overlap_range_start, overlap_range_end)
            # Check `distance` and `within` modifiers.
            if content['distance'] or content['within']:
                logger.debug(f"\tPreceding data chunk end index: [{self.preceding_data_chunk_end_index}]")
                logger.debug(f"\tRelative modifiers: [{content['distance']}] to [{content['within']}]")
                valid_range_start = self.preceding_data_chunk_end_index + int(content['distance'] or 0)
                valid_range_end = (valid_range_start + int(content['within'])) if content['within'] else -1
                logger.debug(f"\tAbsolute modifiers: [{valid_range_start}] to [{valid_range_end}]")
                if chosen_range:
                    overlap_range_start = max(valid_range_start, chosen_range[0])
                    overlap_range_end = valid_range_end if chosen_range[1] == -1 else min(
                        valid_range_end,
                        chosen_range[1])
                else:
                    overlap_range_start = max(valid_range_start, position[0])
                    overlap_range_end = valid_range_end if position[1] == -1 else min(valid_range_end, position[1])
                if overlap_range_end != -1 and overlap_range_end - overlap_range_start < len(data):
                    logger.debug(f"\tNot suitable: [{position[0]}] to [{position[1]}].")
                    continue
                chosen_range = (overlap_range_start, overlap_range_end)
        if chosen_range:
            logger.debug(f"\t[{data}] at [{chosen_range[0]}].")
            self.preceding_data_chunk_end_index = chosen_range[0] + len(data)
            self.data_chunks.append(DataChunk(chosen_range[0], data))
            return True
        else:
            logger.debug(f"\tAdd signature failed: no suitable position.")
            return False

    def push_pcre(self, pcre: Pcre) -> bool:
        # TODO: check the `negated` modifier more carefully.
        if pcre['negated']:
            logger.debug(f"\tSkip signature - Negated.")
            return True

        try:
            data = exrex.getone(pcre['match']).encode("utf-8")
        except:
            logger.debug(f"\tGenerating data from regex failed [{pcre['match']}].")
            return False

        if pcre['R']:
            # If `R` flag exists, put it at last.
            start_inx = self.preceding_data_chunk_end_index
            logger.debug(f"\t[{data}] at [{start_inx}] - Pcre with `R`.")
            self.preceding_data_chunk_end_index = start_inx + len(data)
            self.data_chunks.append(DataChunk(start_inx, data))
        else:
            # If `R` flag not exists, it is a global pcre, append it to the pcre list.
            logger.debug(f"\t[{data}] - Pcre without `R`.")
            self.global_pcre_data.append(data)
            # For better satisfy the rule, also put it at last.
            start_inx = self.preceding_data_chunk_end_index
            logger.debug(f"\t[{data}] at [{start_inx}] - Pcre without `R`.")
            self.preceding_data_chunk_end_index = start_inx + len(data)
            self.data_chunks.append(DataChunk(start_inx, data))
        return True

    def push_isdataat(self, isdataat: Isdataat) -> bool:
        return super().push_isdataat(isdataat)

class BlendingMutator(PassThroughMutator):

    def __init__(self, ruleset: RuleSet):
        super().__init__(ruleset)

        logger.info(f'Blending mutator initialized.')

    def is_valid(self, *rules: Rule, proto: str) -> bool:
        if len(rules) < 2:
            logger.warning(f'Expected at least 2 rule, got {len(rules)}')
            return False

        return True

    def mutate_signatures(self, *rules: Rule) -> dict[str, list[Option]]:
        return super().mutate_signatures(*rules)

    def render_signatures(self, sticky_buffer, proto) -> PassThroughSignatureRender:
        return BlendingSignatureRender(sticky_buffer, proto)