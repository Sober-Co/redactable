from redactable.decors import redactable_io
from redactable.policy import PolicyBuilder


def sample_policy():
    return PolicyBuilder(name="email-policy").redact("email").build()


def test_redactable_io_redacts_output():
    @redactable_io(policy=sample_policy())
    def build_message(address: str) -> str:
        return f"Contact me at {address}"

    output = build_message("test@example.com")
    assert "[REDACTED:EMAIL]" in output


def test_redactable_io_passes_through_non_string():
    data = {"email": "test@example.com"}

    @redactable_io(policy=sample_policy())
    def get_data():
        return data

    assert get_data() is data


def test_redactable_io_can_return_findings():
    @redactable_io(policy=sample_policy(), return_findings=True)
    def build_message(address: str) -> str:
        return f"Contact me at {address}"

    output, findings = build_message("test@example.com")
    assert "[REDACTED:EMAIL]" in output
    assert any(f.kind == "email" for f in findings)
