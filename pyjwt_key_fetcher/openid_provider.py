from typing import Any, Dict, Optional

import aiocache  # type: ignore

from pyjwt_key_fetcher.errors import JWTKeyNotFoundError, JWTOpenIDConnectError
from pyjwt_key_fetcher.http_client import HTTPClient
from pyjwt_key_fetcher.key import Key


class OpenIDProvider:
    def __init__(self, iss: str, http_client: HTTPClient) -> None:
        self.iss = iss
        self.http_client = http_client
        self._openid_configuration: Optional[Dict[str, Any]] = None
        self._jwk_map: Dict[str, Dict[str, Any]] = {}
        self.keys: Dict[str, Key] = {}

    async def get_openid_configuration(self) -> Dict[str, Any]:
        """
        Get the OpenID configuration.

        :return: The OpenID Configuration as a dictionary.
        :raise JWTHTTPFetchError: If there's a problem fetching the data.
        """
        if self._openid_configuration is None:
            url = f"{self.iss.rstrip('/')}/.well-known/openid-configuration"
            self._openid_configuration = await self.http_client.get_json(url)

        return self._openid_configuration

    async def _get_jwks_uri(self) -> str:
        """
        Retrieve the uri to JWKs.

        :return: The uri to the JWKs.
        :raise JWTHTTPFetchError: If there's a problem fetching the data.
        :raise JWTOpenIDConnectError: If the data doesn't contain "jwks_uri".
        """
        conf = await self.get_openid_configuration()
        try:
            jwks_uri = conf["jwks_uri"]
        except KeyError as e:
            raise JWTOpenIDConnectError(
                "Missing 'jwks_uri' in OpenID Connect configuration"
            ) from e
        return jwks_uri

    @aiocache.cached(ttl=300)
    async def _fetch_jwk_map(self) -> Dict[str, Dict[str, Any]]:
        """
        Get all JWKs for an issuer as a dictionary with kid as key.

        Rate limited to once per 5 minutes (300 seconds).

        :return: A mapping of {kid: {<data_for_the_kid>}, ...}
        :raise JWTHTTPFetchError: If there's a problem fetching the data.
        :raise JWTOpenIDConnectError: If the data doesn't contain "jwks_uri".
        """
        jwks_uri = await self._get_jwks_uri()
        data = await self.http_client.get_json(jwks_uri)
        try:
            jwks_list = data["keys"]
        except KeyError as e:
            raise JWTOpenIDConnectError(f"Missing 'jwks' in {jwks_uri}") from e

        jwk_map = {jwk["kid"]: jwk for jwk in jwks_list}

        return jwk_map

    async def get_jwk_data(self, kid: str) -> Dict[str, Any]:
        """
        Get the raw data for a jwk based on kid.

        :param kid: The key ID.
        :return: The raw JWK data as a dictionary.
        :raise JWTHTTPFetchError: If there's a problem fetching the data.
        :raise JWTOpenIDConnectError: If the data doesn't contain "jwks_uri".
        :raise JWTKeyNotFoundError: If no matching kid was found.
        """
        if kid not in self._jwk_map:
            self._jwk_map = await self._fetch_jwk_map()
        try:
            return self._jwk_map[kid]
        except KeyError:
            raise JWTKeyNotFoundError

    async def get_key(self, kid: str) -> Key:
        """
        Get the Key for a particular kid.

        :param kid: The key id.
        :return: The Key.
        :raise JWTHTTPFetchError: If there's a problem fetching the data.
        :raise JWTOpenIDConnectError: If the data doesn't contain "jwks_uri".
        :raise JWTKeyNotFoundError: If no matching kid was found.
        """
        if kid not in self.keys:
            key = Key(await self.get_jwk_data(kid))
            self.keys[kid] = key

        return self.keys[kid]
