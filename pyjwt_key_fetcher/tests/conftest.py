from datetime import datetime, timedelta
from functools import cached_property
from hashlib import sha256
from typing import Any, Dict, Optional
from unittest.mock import MagicMock
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from pyjwt_key_fetcher import KeyFetcher
from pyjwt_key_fetcher.errors import JWTHTTPFetchError
from pyjwt_key_fetcher.http_client import HTTPClient
from pyjwt_key_fetcher.utils import unsigned_int_to_urlsafe_b64


class RSAPrivateKeyWrapper:
    def __init__(self):
        self.privkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    @cached_property
    def n(self):
        n = self.privkey.public_key().public_numbers().n
        return unsigned_int_to_urlsafe_b64(n)

    @cached_property
    def e(self):
        e = self.privkey.public_key().public_numbers().e
        return unsigned_int_to_urlsafe_b64(e)

    @cached_property
    def kid(self):
        return sha256(f"rsa:{self.e}:{self.n}".encode()).hexdigest()[:32]

    @property
    def alg(self):
        return "RS256"

    @cached_property
    def jwk(self):
        return {
            "kid": self.kid,
            "kty": "RSA",
            "use": "sig",
            "alg": self.alg,
            "n": self.n,
            "e": self.e,
        }

    @cached_property
    def public_pem(self) -> bytes:
        return self.privkey.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )


class MockProvider:
    def __init__(self, iss: str = "https://example.com", aud: str = "default_audience"):
        self.iss = iss
        self.aud = aud
        self.keys = []
        self.generate_new_key()

    def generate_new_key(self):
        self.keys.insert(0, RSAPrivateKeyWrapper())

    @property
    def default_key(self):
        return self.keys[0]

    def get_jwks(self):
        return {"keys": [key_wrapper.jwk for key_wrapper in self.keys]}

    def create_token(self, payload: Optional[Dict[str, Any]] = None) -> str:
        """
        Create/issue a JWT token signed by this issuer.
        """
        if not payload:
            payload = {}

        now = datetime.utcnow()
        default_values = {
            "sub": str(uuid4()),
            "aud": self.aud,
            "iss": self.iss,
            "iat": now,
            "exp": now + timedelta(hours=1),
        }

        payload = {**default_values, **payload}

        key = self.default_key
        headers = {"kid": key.kid}
        token = jwt.encode(
            payload=payload, key=key.privkey, algorithm=key.alg, headers=headers
        )

        return token


class MockHTTPClient(HTTPClient):
    """
    A mock client used for tests.
    """

    BASE_URL = "https://example.com"
    OPENID_CONFIG_URL = f"{BASE_URL}/.well-known/openid-configuration"
    JWKS_URL = f"{BASE_URL}/.well-known/jwks"

    def __init__(self, provider: MockProvider) -> None:
        self.provider = provider
        self.get_jwks = MagicMock(wraps=self.get_jwks)
        self.get_openid_configuration = MagicMock(wraps=self.get_openid_configuration)

    async def get_json(self, url: str) -> Dict[str, Any]:
        """
        Get and parse JSON data from a URL.

        :param url: The URL to fetch the data from.
        :return: The JSON Data as a dictionary.
        :raise JWTHTTPFetchError: If there's a problem fetching the data.
        """
        if not (url.startswith("https://") or url.startswith("http://")):
            raise JWTHTTPFetchError("Unsupported protocol in 'iss'")

        if url == self.OPENID_CONFIG_URL:
            return self.get_openid_configuration()
        elif url == self.JWKS_URL:
            return self.get_jwks()
        else:
            raise JWTHTTPFetchError(f"Failed to fetch or decode {url}")

    def get_jwks(self) -> Dict[str, Any]:
        return self.provider.get_jwks()

    def get_openid_configuration(self) -> Dict[str, Any]:
        return {
            "jwks_uri": self.JWKS_URL,
        }


@pytest.fixture
def create_provider_fetcher_and_client():
    async def _create(valid_issuers=None):
        provider = MockProvider()
        http_client = MockHTTPClient(provider=provider)
        fetcher = KeyFetcher(valid_issuers=valid_issuers, http_client=http_client)
        return provider, fetcher, http_client

    return _create
