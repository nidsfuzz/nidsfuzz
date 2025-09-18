import copy
import random

from logger import logger
from generation.PassThroughMutator import PassThroughSignatureRender, PassThroughMutator
from generation.obfs import UrlEncoding, PathShifting
from rule import Content, Pcre, Isdataat, ByteTest, Option, RuleSet, Proto, ProtoType, Rule

"""
    This strategy simulates obfuscation attacks by applying two manipulations to rule signatures:
        (i) Replacing: replace specific characters with encoded ones.
        (ii) Inserting: insert given characters in particular positions.

    Replacing randomly picks up spaces and underlines in signatures, and then replaces
    them with encoded characters in the generated strings.
    According to RFC 3986, percent encoding is used to represent certain reserved characters,
    invisible characters (such as spaces), and characters that cannot be directly included in URLs.
    @see https://datatracker.ietf.org/doc/html/rfc3986

    Inserting only occurs before or after special characters instead of in between letters.
    Currently, only one insertion pattern is supported:
        (i) Inserting an arbitrary number of "./" or "/." either before or after the character "/".
"""

class ObfuscationSignatureRender(PassThroughSignatureRender):
    REPLACING = UrlEncoding()
    INSERTING = PathShifting()

    def __init__(self, sticky_buffer: str, protocol: str,
                 replace_times: int,
                 insert_times: int, ):
        super().__init__(sticky_buffer, protocol)

        self.replace_times = replace_times
        self.insert_times = insert_times

    def push_content(self, content: Content) -> bool:
        if content['negated']:
            return super().push_content(content=content)

        obfuscated_option = self.obfuscate_option(content)
        return super().push_content(obfuscated_option)

    def push_pcre(self, pcre: Pcre) -> bool:
        if pcre['negated']:
            return super().push_pcre(pcre=pcre)

        obfuscated_option = self.obfuscate_option(pcre)
        return super().push_pcre(obfuscated_option)

    def push_isdataat(self, isdataat: Isdataat) -> bool:
        return super().push_isdataat(isdataat)

    def push_bytetest(self, bytetest: ByteTest) -> bool:
        return super().push_bytetest(bytetest)

    def obfuscate_option(self, origin_option: Option) -> Option:
        # It is forbidden to modify the original rule in the RuleSet
        obfuscated_option = copy.deepcopy(origin_option)

        if isinstance(obfuscated_option, Content):
            raw_content = obfuscated_option.ascii_matches
            obfuscated_content: str = self.INSERTING.obfuscate(origin=raw_content, obfuscate_times=self.insert_times)
            obfuscated_content: str = self.REPLACING.obfuscate(origin=obfuscated_content, obfuscate_times=self.replace_times)

            if "|" in obfuscated_content:
                obfuscated_content = obfuscated_content.replace("|", "|7C|")
            obfuscated_option['match'] = obfuscated_content
            logger.debug(f'\tObfuscated content: "{raw_content}" -> "{obfuscated_content}"')

        elif isinstance(obfuscated_option, Pcre):
            # TODO: How to obfuscate the value of PCRE ?
            # logger.debug(f'\tObfuscated pcre: "{raw_pcre}" -> "{obfuscated_pcre}"')
            pass
        else:
            logger.warning(f'Unsupported type of option for obfuscation: {obfuscated_option.__class__.__name__}')
        return obfuscated_option


class ObfuscationMutator(PassThroughMutator):

    def __init__(self, ruleset: RuleSet,
                 replace_times: int = 10,
                 insert_times: int = 3,
                 min_obfuscate_times: int = 1,
                 max_obfuscate_times: int = 50, ):
        super().__init__(ruleset)
        if min_obfuscate_times > max_obfuscate_times:
            logger.error(
                f'The minimum obfuscation times [{min_obfuscate_times}] must be smaller than the maximum obfuscation times [{max_obfuscate_times}].')
            raise ValueError(
                f'The minimum obfuscation times [{min_obfuscate_times}] must be smaller than the maximum obfuscation times [{max_obfuscate_times}].')

        if not min_obfuscate_times <= replace_times <= max_obfuscate_times:
            logger.error(
                f'The replace times should be in the range [{min_obfuscate_times}, {max_obfuscate_times}], but got [{replace_times}].')
            raise ValueError(
                f'The replace times should be in the range [{min_obfuscate_times}, {max_obfuscate_times}], but got [{replace_times}].')

        if not min_obfuscate_times <= insert_times <= max_obfuscate_times:
            logger.error(
                f'The insert times should be in the range [{min_obfuscate_times}, {max_obfuscate_times}], but got [{insert_times}].')
            raise ValueError(
                f'The insert times should be in the range [{min_obfuscate_times}, {max_obfuscate_times}], but got [{insert_times}].')

        self.replace_times = replace_times
        self.insert_times = insert_times
        self.min_obfuscate_times = min_obfuscate_times
        self.max_obfuscate_times = max_obfuscate_times

        logger.info(f'Obfuscation mutator initialized.')

    def mutate_signatures(self, *rules: Rule) -> dict[str, list[Option]]:
        return super().mutate_signatures(*rules)

    def is_valid(self, *rules: Rule, proto: str) -> bool:
        if Proto.lookup(proto.lower()).type != ProtoType.TEXT:
            logger.error(f"Obfuscation strategy only works for text-based protocols, but got: {proto}")
            raise NotImplementedError(f"Obfuscation strategy only works for text-based protocols, but got: {proto}")

        return True

    def render_signatures(self, sticky_buffer, proto) -> PassThroughSignatureRender:
        # These obfuscation times are randomly selected, and the probability follows a Gaussian distribution.
        replace_times = int(random.triangular(low=self.min_obfuscate_times, high=self.max_obfuscate_times,
                                              mode=self.replace_times))
        insert_times = int(random.triangular(low=self.min_obfuscate_times, high=self.max_obfuscate_times,
                                             mode=self.insert_times))
        logger.debug(f'Replace times: {replace_times}')
        logger.debug(f'Insert times: {insert_times}')
        return ObfuscationSignatureRender(sticky_buffer, proto, replace_times, insert_times)