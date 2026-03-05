"""Quick smoke test for the redactable package."""

from redactable import apply

text = "Email alice@example.com, card 4111 1111 1111 1111"
print("Original:", text)
print("No policy:", apply(text, region="GB"))
print("With GDPR:", apply(text, policy="gdpr.yaml", region="GB"))
