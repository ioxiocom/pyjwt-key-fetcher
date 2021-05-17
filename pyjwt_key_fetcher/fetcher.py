from typing import Any, Dict, Iterable, Optional

import asyncstdlib as a
import jwt

from pyjwt_key_fetcher.errors import JWTFormatError, JWTOpenIDConnectError
from pyjwt_key_fetcher.http_client import DefaultHTTPClient, HTTPClient
from pyjwt_key_fetcher.key import Key


class AsyncKeyFetcher:
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
        self.get_key_by_iss_and_kid = a.lru_cache(maxsize=cache_maxsize)(
            self.get_key_by_iss_and_kid
        )

    @staticmethod
    def get_kid(token: str) -> str:
        """
        Get the kid from the token.

        :param token: The JWT token.
        :return: The kid (key id) from the token.
        :raise JWTFormatException: If the token doesn't have a "kid".
        :raise PyJWTError: If the token can't be decoded.
        """
        jwt_headers = jwt.get_unverified_header(token)
        try:
            kid = jwt_headers["kid"]
        except KeyError:
            raise JWTFormatError("Missing 'kid' in header")
        return kid

    def _get_issuer(self, token: str) -> str:
        """
        Get the issuer from the token (without verification).

        :param token: The JWT token (as a string).
        :return: The issuer.
        :raise JWTFormatException: If the token doesn't have a valid "iss".
        :raise PyJWTError: If the token can't be decoded.
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
        :raise JWTHTTPFetchError: If there's a problem fetching the data.
        :raise JWTOpenIDConnectError: If the data doesn't contain "jwks_uri".
        """
        jwks_uri = await self._get_jwks_uri_from_iss(iss)
        data = await self.http_client.get_json(jwks_uri)
        try:
            jwks_list = data["keys"]
        except KeyError as e:
            raise JWTOpenIDConnectError(f"Missing 'jwks' in {jwks_uri}") from e

        jwk_map = {jwk["kid"]: jwk for jwk in jwks_list}

        return jwk_map

    async def get_key_by_iss_and_kid(self, iss: str, kid: str) -> Key:
        """
        Get the key based on "iss" and "kid".

        :param iss: The "iss" (issuer) of the JWT.
        :param kid: The "kid" (key id) from the header of the JWT.
        :return: The key.
        :raise JWTHTTPFetchError: If there's a problem fetching the data.
        :raise JWTOpenIDConnectError: If the data doesn't contain "jwks_uri".
        """
        jwks = await self._get_jwks(iss)
        return Key(jwks[kid])

    async def get_key(self, token: str) -> Key:
        """
        Get the key based on given token.

        :param token: The JWT as a string.
        :return: The key.
        :raise JWTFormatException: If the token doesn't have a "kid".
        :raise JWTFormatException: If the token doesn't have a valid "iss".
        :raise JWTHTTPFetchError: If there's a problem fetching the data.
        :raise JWTOpenIDConnectError: If the data doesn't contain "jwks_uri".
        :raise PyJWTError: If the token can't be decoded.
        """
        kid = self.get_kid(token)
        iss = self._get_issuer(token)
        key = await self.get_key_by_iss_and_kid(iss=iss, kid=kid)
        return key
