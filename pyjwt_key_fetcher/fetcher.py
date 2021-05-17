import collections.abc
from typing import Any, Dict, Iterable, Iterator, Optional

import asyncstdlib as a
import jwt
from jwt import PyJWK

from pyjwt_key_fetcher.errors import JWTFormatError, JWTOpenIDConnectError
from pyjwt_key_fetcher.http_client import DefaultHTTPClient, HTTPClient


class KeyWrapper(collections.abc.Mapping):
    """
    Wrapper for the JWT key and algorithm.
    """

    def __init__(self, jwk_data: Dict[str, Any]) -> None:
        """
        :param jwk_data: The data from the JWKs JSON for a key.
        """
        pyjwt = PyJWK(jwk_data)

        self.__kid = pyjwt.key_id

        self.key: PyJWK = pyjwt.key
        self.algorithms = [jwk_data["alg"]]

    @property
    def dct(self) -> Dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if not k.startswith("_")}

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(key=<{self.key.__class__.__name__}, kid: "
            f"{self.__kid}>, algorithms={self.algorithms})"
        )

    def __getitem__(self, item):
        return self.dct.__getitem__(item)

    def __iter__(self) -> Iterator:
        return self.dct.__iter__()

    def __len__(self) -> int:
        return self.dct.__len__()


class KeyFetcher:
    def __init__(
        self,
        valid_issuers: Optional[Iterable] = None,
        http_client: HTTPClient = None,
        cache_maxsize: int = 128,
    ) -> None:

        if not http_client:
            http_client = DefaultHTTPClient()
        self.http_client = http_client

        if not valid_issuers:
            valid_issuers = set()
        self.valid_issuers = set(valid_issuers)

        # Apply the a.lru_cache decorator without syntactic sugar to be able to
        # customize the maxsize
        self.get_key = a.lru_cache(maxsize=cache_maxsize)(self.get_key)

    @staticmethod
    def _get_kid(token: str) -> str:
        """
        Get the kid from the token

        :param token: The JWT token.
        :return: The kid (key id) from the token
        :raise JWTFormatException: If the token doesn't have a "kid".
        :raise PyJWTError: If the token can't be decoded
        """
        jwt_headers = jwt.get_unverified_header(token)
        try:
            kid = jwt_headers["kid"]
        except KeyError:
            raise JWTFormatError("Missing 'kid' in header")
        return kid

    def _get_issuer(self, token: str) -> str:
        """
        Get the issuer from the token (without verification)

        :param token: The JWT token (as a string).
        :return: The issuer.
        :raise JWTFormatException: If the token doesn't have a valid "iss".
        :raise PyJWTError: If the token cant be decoded.
        """
        payload = jwt.decode(token, options={"verify_signature": False})
        try:
            issuer = payload["iss"]
        except KeyError:
            raise JWTFormatError("Missing 'iss' in payload")

        if self.valid_issuers and issuer not in self.valid_issuers:
            raise JWTFormatError(f"Invalid 'iss' in payload: '{issuer}'")

        return issuer

    async def _get_openid_configuration(self, iss: str) -> Dict[str, Any]:
        """
        Get the OpenID configuration based on the issuer.

        :param iss: The issuer of the token.
        :return: The OpenID Configuration as a dictionary.
        :raise JWTHTTPFetchError: If there's a problem fetching the data.
        """
        if iss.endswith("/"):
            iss = iss[:-1]
        url = f"{iss}/.well-known/openid-configuration"
        data = await self.http_client.get_json(url)
        return data

    async def _get_jwks_uri_from_iss(self, iss) -> str:
        """
        Retrieve the uri to jwks.

        :param iss: The issuer
        :return: The uri to the jwks
        :raise JWTHTTPFetchError: If there's a problem fetching the data.
        :raise JWTOpenIDConnectError: If the data doesn't contain "jwks_uri".
        """
        conf = await self._get_openid_configuration(iss)
        try:
            jwks_uri = conf["jwks_uri"]
        except KeyError as e:
            raise JWTOpenIDConnectError(
                "Missing 'jwks_uri' in OpenID Connect configuration"
            ) from e
        return jwks_uri

    async def _get_jwks(self, iss: str) -> Dict[str, Dict[str, Any]]:
        """
        Get all jwks for an issuer as a dictionary with kid as key.

        :param iss: The issuer
        :return: A mapping of kid: {<data_for_the_kid>}
        """
        jwks_uri = await self._get_jwks_uri_from_iss(iss)
        data = await self.http_client.get_json(jwks_uri)
        try:
            jwks_list = data["keys"]
        except KeyError as e:
            raise JWTOpenIDConnectError(f"Missing 'jwks' in {jwks_uri}") from e

        jwk_map = {jwk["kid"]: jwk for jwk in jwks_list}

        return jwk_map

    async def get_key(self, iss, kid) -> KeyWrapper:
        jwks = await self._get_jwks(iss)
        return KeyWrapper(jwks[kid])

    async def get_key_from_token(self, token: str) -> KeyWrapper:
        kid = self._get_kid(token)
        iss = self._get_issuer(token)
        key = await self.get_key(iss=iss, kid=kid)
        return key
