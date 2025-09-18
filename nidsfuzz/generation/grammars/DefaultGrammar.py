class DefaultGrammar:

    def __init__(self):
        self.request_fields: dict[str, bytes] = {}
        self.response_fields: dict[str, bytes] = {}

    def generate(self, pkt_type: str) -> bytes:
        if self.request_fields == {} or self.response_fields == {}:
            raise RuntimeError(f'Please populate fields before generating packets.')

        match pkt_type.upper():
            case 'REQUEST':
                field_values = self.request_fields
            case 'RESPONSE':
                field_values = self.response_fields
            case _:
                raise NotImplementedError

        packet = b"".join(field_values.values())
        return packet

    def populate(self, part_fields: dict[str, bytes]):

        def populating(original_fields, populated_fields):
            # Use received field values to replace the default field values.
            for buffer in original_fields.keys():
                if buffer in populated_fields.keys():
                    original_fields[buffer] = populated_fields[buffer]
                    populated_fields.pop(buffer)
            # Put the extra fields received into the message body.
            # And the message body is usually the last field.
            for _, value in populated_fields.items():
                last_field = next(reversed(original_fields))
                original_fields[last_field] += value
            return original_fields

        self.request_fields = populating(
            original_fields=self.templates(pkt_type='REQUEST'),
            populated_fields=part_fields.copy())
        self.response_fields = populating(
            original_fields=self.templates(pkt_type='RESPONSE'),
            populated_fields=part_fields.copy()
        )

    @classmethod
    def templates(cls, pkt_type: str) -> dict[str, bytes]:
        match pkt_type.upper():
            case 'REQUEST':
                return {
                    'pkt_data': b''
                }
            case 'RESPONSE':
                return {
                    'pkt_data': b''
                }
            case _:
                raise NotImplementedError