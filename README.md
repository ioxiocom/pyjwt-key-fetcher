# pyjwt-key-fetcher

[![Build Status](https://travis-ci.com/digitalliving/pyjwt-key-fetcher.svg?branch=master)](https://travis-ci.com/digitalliving/pyjwt-key-fetcher)

Async library to fetch JWKs for JWT tokens.

This library is intended to be used together with
[PyJWT](https://pyjwt.readthedocs.io/en/stable/) to automatically verify keys signed by
OpenID Connect providers. It retrieves the `iss` (issuer) and the `kid` (key ID) from
the JWT, fetches the `.well-known/openid-configuration` from the issuer to find out the
`jwks_uri` and fetches that to find the right key.

This should give similar ability to verify keys as for example
[https://jwt.io/](https://jwt.io/), where you can just paste in a token, and it will
automatically reach out and retrieve the key for you.

The `AsyncKeyFetcher` provided by this library acts as an improved async replacement for
[PyJWKClient](https://pyjwt.readthedocs.io/en/2.1.0/usage.html#retrieve-rsa-signing-keys-from-a-jwks-endpoint).

## Installation

The package is available on PyPI:

```bash
pip install pyjwt-key-fetcher
```

## Usage

### Example

```python
import asyncio

import jwt

from pyjwt_key_fetcher import AsyncKeyFetcher


async def main():
    fetcher = AsyncKeyFetcher()
    # Token and options copied from
    # https://pyjwt.readthedocs.io/en/2.1.0/usage.html#retrieve-rsa-signing-keys-from-a-jwks-endpoint
    token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik5FRTFRVVJCT1RNNE16STVSa0ZETlRZeE9UVTFNRGcyT0Rnd1EwVXpNVGsxUWpZeVJrUkZRdyJ9.eyJpc3MiOiJodHRwczovL2Rldi04N2V2eDlydS5hdXRoMC5jb20vIiwic3ViIjoiYVc0Q2NhNzl4UmVMV1V6MGFFMkg2a0QwTzNjWEJWdENAY2xpZW50cyIsImF1ZCI6Imh0dHBzOi8vZXhwZW5zZXMtYXBpIiwiaWF0IjoxNTcyMDA2OTU0LCJleHAiOjE1NzIwMDY5NjQsImF6cCI6ImFXNENjYTc5eFJlTFdVejBhRTJINmtEME8zY1hCVnRDIiwiZ3R5IjoiY2xpZW50LWNyZWRlbnRpYWxzIn0.PUxE7xn52aTCohGiWoSdMBZGiYAHwE5FYie0Y1qUT68IHSTXwXVd6hn02HTah6epvHHVKA2FqcFZ4GGv5VTHEvYpeggiiZMgbxFrmTEY0csL6VNkX1eaJGcuehwQCRBKRLL3zKmA5IKGy5GeUnIbpPHLHDxr-GXvgFzsdsyWlVQvPX2xjeaQ217r2PtxDeqjlf66UYl6oY6AqNS8DH3iryCvIfCcybRZkc_hdy-6ZMoKT6Piijvk_aXdm7-QQqKJFHLuEqrVSOuBqqiNfVrG27QzAPuPOxvfXTVLXL2jek5meH6n-VWgrBdoMFH93QEszEDowDAEhQPHVs0xj7SIzA"
    key_entry = await fetcher.get_key(token)
    token = jwt.decode(
        jwt=token,
        options={"verify_exp": False},
        audience="https://expenses-api",
        **key_entry
    )
    print(token)


if __name__ == "__main__":
    asyncio.run(main())
```

### Options

#### Limiting issuers

You can limit the issuers you allow fetching keys from by setting the `valid_issuers`
when creating the `AsyncKeyFetcher`, like this:

```python
AsyncKeyFetcher(valid_issuers=["https://example.com"])
```

#### Adjusting caching

The `AsyncKeyFetcher` will by default cache data for up to 32 different issuers with a
TTL of 3600 seconds (1 hour) each. This means that in case of key-revocation, the key
will be trusted for up to 1 hour after it was removed from the JWKs.

If a previously unseen kid for an already seen issuer is seen, it will trigger a
re-fetch of the JWKs, provided they have not been fetched in the past 5 minutes, in
order to rather quickly react to new keys being published.

The amount of issuers to cache data for, as well as the cache time for the data can be
adjusted like this:

```python
AsyncKeyFetcher(cache_maxsize=10, cache_ttl=2*60*60)
```

The minimum interval for checking for new keys can for now not be adjusted.

#### Using your own HTTP Client

The library ships with a `DefaultHTTPClient` that uses `aiohttp` for fetching the JSON
data; the openid-configuration and the jwks. If you want, you can write your own custom
client by inheriting from the `HTTPClient`. The only requirement is that it implements
an async function to fetch JSON from a given URL and return it as a dictionary.
