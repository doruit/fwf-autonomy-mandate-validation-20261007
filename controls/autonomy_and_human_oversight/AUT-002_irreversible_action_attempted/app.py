"""Chainlit entry point for the AUT-002 live demo."""

import truststore

truststore.inject_into_ssl()

from src.aut_002 import cloud_chat as _aut_002_chat  # noqa: E402, F401