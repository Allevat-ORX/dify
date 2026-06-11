"""
Field Encoding/Decoding Utilities

Provides Base64 decoding for sensitive fields (password, verification code)
received from the frontend.

Note: This uses Base64 encoding for obfuscation, not cryptographic encryption.
Real security relies on HTTPS for transport layer encryption.
"""

import base64
import logging

logger = logging.getLogger(__name__)


class FieldEncryption:
    """Handle decoding of sensitive fields during transmission"""

    @classmethod
    def decrypt_field(cls, encoded_text: str) -> str:
        """
        Decode Base64 encoded field from frontend.

        Args:
            encoded_text: Base64 encoded text from frontend

        Returns:
            Decoded plaintext, or original text unchanged if not valid base64
        """
        try:
            # Decode base64
            decoded_bytes = base64.b64decode(encoded_text)
            decoded_text = decoded_bytes.decode("utf-8")
            logger.debug("Field decoding successful")
            return decoded_text

        except Exception:
            # Not valid base64 — treat as plain text (frontend may send unencoded).
            # Known limitation: a plain-text password that is also valid base64
            # (e.g. purely alphanumeric) will be silently decoded. To fix properly,
            # require frontend to prefix encoded values with "b64:" and check here.
            return encoded_text

    @classmethod
    def decrypt_password(cls, encrypted_password: str) -> str:
        """
        Decrypt password field

        Args:
            encrypted_password: Encrypted password from frontend

        Returns:
            Decrypted password, or original text unchanged if not valid base64
        """
        return cls.decrypt_field(encrypted_password)

    @classmethod
    def decrypt_verification_code(cls, encrypted_code: str) -> str:
        """
        Decrypt verification code field

        Args:
            encrypted_code: Encrypted code from frontend

        Returns:
            Decrypted code, or original text unchanged if not valid base64
        """
        return cls.decrypt_field(encrypted_code)
