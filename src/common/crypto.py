"""cipher.py

Lightweight wire-safe encryption helpers using AES-GCM with base64
transport encoding. The functions here keep the API small and string
friendly for the rest of the project:

- `generate_key()` -> base64 urlsafe string representing a 32-byte key
- `encrypt_message(plaintext, key_b64)` -> base64 urlsafe ciphertext
- `decrypt_message(token_b64, key_b64)` -> plaintext string

This requires the `cryptography` package. If you prefer not to use
real encryption, we can provide a simple base64 fallback, but AES-GCM
is strongly recommended for confidentiality and authenticity.
"""

from __future__ import annotations

import base64
import os
from typing import Tuple

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception as e:
    raise ImportError("cryptography package is required for cipher.py: install with 'pip install cryptography'") from e


def generate_key() -> str:
    """Generate a 256-bit key and return it as a urlsafe base64 string."""
    key = os.urandom(32)
    return base64.urlsafe_b64encode(key).decode('ascii')


def _b64_to_key(key_b64: str) -> bytes:
    return base64.urlsafe_b64decode(key_b64.encode('ascii'))


def encrypt_message(plaintext: str, key_b64: str) -> str:
    """Encrypt `plaintext` using AES-GCM and return urlsafe-base64 token.

    The returned token contains nonce || ciphertext-with-tag encoded
    with urlsafe base64, so it is safe to send over text TCP channels.
    """
    key = _b64_to_key(key_b64)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    token = nonce + ct
    return base64.urlsafe_b64encode(token).decode('ascii')


def decrypt_message(token_b64: str, key_b64: str) -> str:
    """Decrypt a token produced by `encrypt_message` and return plaintext.

    Raises an exception if authentication fails.
    """
    key = _b64_to_key(key_b64)
    token = base64.urlsafe_b64decode(token_b64.encode('ascii'))
    nonce = token[:12]
    ct = token[12:]
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, None)
    return pt.decode('utf-8')


def split_token(token_b64: str) -> Tuple[bytes, bytes]:
    """Return (nonce, ciphertext_with_tag) from token (for debugging/tests)."""
    token = base64.urlsafe_b64decode(token_b64.encode('ascii'))
    return token[:12], token[12:]