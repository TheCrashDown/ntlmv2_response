import hmac
import hashlib
import secrets


def random_byte_sequence(n: int) -> bytes:
    """Generate random n-byte sequence"""

    return secrets.token_bytes(n)


def concat_identity(username: str, domain: str) -> bytes:
    """Concatenate username and domain in uppercase Unicode"""
    return (
        username.upper().encode("utf-16le")
        + b"\x00"
        + domain.upper().encode("utf-16le")
    )


def generate_ntlmv2_response(
    username: str, password: str, domain: str, server_challenge: bytes
) -> bytes:
    """
    Generate the NTLMv2 response for the given username, password, domain, and server challenge.

    Args:
        username (str): The username
        password (str): The password
        domain (str): The domain
        server_challenge (bytes): The server challenge

    Returns:
        bytes: The NTLMv2 response
    """
    password_hash = hashlib.new("md4", password.encode("utf-16le")).digest()

    client_challenge = random_byte_sequence(8)

    identity = concat_identity(username, domain)

    user_hash = hmac.new(password_hash, identity, hashlib.md5).digest()
    blob = user_hash + client_challenge
    hashed_blob = hmac.new(user_hash, blob + server_challenge, hashlib.md5).digest()

    return hashed_blob + blob


def check_ntlmv2_response(
    hashed_password: bytes,
    username: str,
    domain: str,
    ntlm_response: bytes,
    server_challenge: bytes,
) -> bool:
    """
    Check the correctness of NTLMv2 response

    Args:
        hashed_password (bytes): The hashed password from database
        username (str): The username
        domain (str): The domain
        ntlm_response (bytes): The NTLMv2 response to check
        server_challenge (bytes): The server challenge, that was sent to Client to make response
    Returns:
        bool: True if the response is correct, False otherwise
    """

    received_blob_hash = ntlm_response[:16]
    client_challenge = ntlm_response[-8:]

    identity = concat_identity(username, domain)
    user_hash = hmac.new(hashed_password, identity, hashlib.md5).digest()

    calculated_blob_hash = hmac.new(
        user_hash, user_hash + client_challenge + server_challenge, hashlib.md5
    ).digest()[:16]

    return received_blob_hash == calculated_blob_hash
