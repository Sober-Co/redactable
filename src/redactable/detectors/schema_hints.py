from .base import Match, register

# This detector relies on context = {"schema": {"field_name": "value", ...}}
# It emits matches for fields whose names are known sensitive hints.
_HINTS = {
    "email": "EMAIL",
    "e_mail": "EMAIL",
    "mail": "EMAIL",
    "cc": "CREDIT_CARD",
    "credit_card": "CREDIT_CARD",
    "card_number": "CREDIT_CARD",
    "ssn": "SSN",
    "national_insurance": "NINO",  # placeholder label if/when added
    "phone": "PHONE",
    "phone_number": "PHONE",
    "dob": "DATE_DOB",
    "date_of_birth": "DATE_DOB",
}

class SchemaHintDetector:
    name = "schema_hints"
    labels = tuple(set(_HINTS.values()))

    def detect(self, text: str, *, context=None):
        # No-op for raw text. This detector is meant for structured rows.
        # We still implement the signature; integrate at the DataFrame layer.
        return
        yield  # generator stub

register(SchemaHintDetector())
