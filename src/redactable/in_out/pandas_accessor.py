"""Pandas DataFrame accessor for redactable."""

try:
    import pandas as pd
    from pandas.api.extensions import register_dataframe_accessor
except ImportError:
    pd = None
    register_dataframe_accessor = None


if pd is not None:

    @register_dataframe_accessor("redact")
    class RedactableAccessor:
        """Pandas DataFrame accessor for applying redaction policies."""

        def __init__(self, pandas_obj):
            self._obj = pandas_obj

        def apply(self, policy: str | None = None, *, region: str = "GB"):
            """
            Apply a redaction policy to all string columns in the DataFrame.

            Args:
                policy: Path to YAML/JSON policy file or Policy object.
                region: Default region for phone parsing (e.g., "GB", "US").

            Returns:
                DataFrame with redaction applied to all string columns.
            """
            from redactable import apply as redact_text

            df = self._obj.copy()

            for col in df.columns:
                # Only redact string columns
                if df[col].dtype == "object":
                    df[col] = df[col].apply(
                        lambda x: (
                            redact_text(str(x), policy=policy, region=region)
                            if pd.notna(x)
                            else x
                        )
                    )

            return df
