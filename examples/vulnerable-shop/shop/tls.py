"""TLS client context for the legacy warehouse system."""

import ssl


def warehouse_context() -> ssl.SSLContext:
    return ssl.SSLContext(ssl.PROTOCOL_TLSv1)
