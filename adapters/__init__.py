"""Adapters turn other alert formats into our Alert's fields.

alert_fields() is the one place the CLI and the API call: OCSF findings are
converted, anything else is returned as-is. Either way the caller validates
the result with its own model (Alert in the CLI, the strict AlertRequest in
the API), so the API's limits apply after conversion too.
"""

from adapters import ocsf


def alert_fields(data: object) -> object:
    """Our alert's fields as a dict if `data` is OCSF; otherwise `data` unchanged."""
    if ocsf.is_ocsf(data):
        return ocsf.to_alert(data).model_dump(exclude_none=True)
    return data
