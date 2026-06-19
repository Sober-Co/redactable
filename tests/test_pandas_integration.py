"""Tests for Pandas DataFrame integration."""

import pytest

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False


@pytest.mark.skipif(not HAS_PANDAS, reason="pandas not installed")
def test_dataframe_redact_accessor_basic():
    """Test basic DataFrame redaction using the .redact() accessor."""
    import redactable

    df = pd.DataFrame({
        "email": ["alice@example.com", "bob@example.com"],
        "name": ["Alice", "Bob"],
    })

    redacted = df.redact(policy="policies/gdpr.yaml")

    # Should return a DataFrame
    assert isinstance(redacted, pd.DataFrame)
    # Original should be unchanged
    assert df["email"][0] == "alice@example.com"
    # Redacted version should have changed email
    assert redacted["email"][0] != "alice@example.com"


@pytest.mark.skipif(not HAS_PANDAS, reason="pandas not installed")
def test_dataframe_redact_mixed_types():
    """Test redaction with mixed column types."""
    import redactable

    df = pd.DataFrame({
        "email": ["alice@example.com", "bob@example.com"],
        "age": [25, 30],
        "active": [True, False],
    })

    redacted = df.redact(policy="policies/gdpr.yaml")

    # Email should be redacted
    assert redacted["email"][0] != "alice@example.com"
    # Numbers should remain unchanged (passed through as strings, but not matched)
    assert redacted["age"][0] == 25
    # Booleans should remain unchanged
    assert redacted["active"][0] == True


@pytest.mark.skipif(not HAS_PANDAS, reason="pandas not installed")
def test_dataframe_redact_with_null_values():
    """Test that null values are handled gracefully."""
    import redactable

    df = pd.DataFrame({
        "email": ["alice@example.com", None, "charlie@example.com"],
    })

    redacted = df.redact(policy="policies/gdpr.yaml")

    # Null should remain null
    assert pd.isna(redacted["email"][1])
    # Non-null values should be redacted
    assert redacted["email"][0] != "alice@example.com"


@pytest.mark.skipif(not HAS_PANDAS, reason="pandas not installed")
def test_dataframe_redact_preserves_index():
    """Test that DataFrame redaction preserves the index."""
    import redactable

    df = pd.DataFrame({
        "email": ["alice@example.com", "bob@example.com"],
    }, index=["row_a", "row_b"])

    redacted = df.redact(policy="policies/gdpr.yaml")

    # Index should be preserved
    assert list(redacted.index) == ["row_a", "row_b"]


@pytest.mark.skipif(not HAS_PANDAS, reason="pandas not installed")
def test_dataframe_redact_credit_cards():
    """Test redaction of credit card numbers."""
    import redactable

    df = pd.DataFrame({
        "cc": ["4111111111111111", "5500000000000004"],
    })

    redacted = df.redact(policy="policies/pci.yaml")

    # Credit cards should be transformed
    assert redacted["cc"][0] != "4111111111111111"


@pytest.mark.skipif(not HAS_PANDAS, reason="pandas not installed")
def test_dataframe_redact_region_parameter():
    """Test that region parameter is passed through."""
    import redactable

    df = pd.DataFrame({
        "phone": ["+447911123456", "+12025551234"],
    })

    redacted = df.redact(policy="policies/gdpr.yaml", region="GB")

    # Should not crash with region parameter
    assert isinstance(redacted, pd.DataFrame)
