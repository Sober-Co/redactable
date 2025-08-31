from .base import register

_HINTS = {
    "email": "EMAIL",
    "e_mail": "EMAIL",
    "mail": "EMAIL",
    "cc": "CREDIT_CARD",
    "credit_card": "CREDIT_CARD",
    "card_number": "CREDIT_CARD",
    "ssn": "SSN",
    "national_insurance": "NINO",
    "phone": "PHONE",
    "phone_number": "PHONE",
    "dob": "DATE_DOB",
    "date_of_birth": "DATE_DOB",
}

class SchemaHintDetector:
    name = "schema_hints"
    labels = tuple(set(_HINTS.values()))

    def detect(self, text: str, *, context=None):
        return
        yield  # generator stub

register(SchemaHintDetector())
