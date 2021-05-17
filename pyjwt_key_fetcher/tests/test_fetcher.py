import jwt
import pytest


@pytest.mark.asyncio
async def test_fetching_key(create_provider_fetcher_and_client):
    provider, fetcher, client = await create_provider_fetcher_and_client()

    token = provider.create_token()
    key_entry = await fetcher.get_key(token)
    jwt.decode(token, audience=provider.aud, **key_entry)

    client.get_openid_configuration.assert_called_once()
    client.get_jwks.assert_called_once()


@pytest.mark.asyncio
async def test_fetching_same_key_only_once(create_provider_fetcher_and_client):
    provider, fetcher, client = await create_provider_fetcher_and_client()

    token = provider.create_token()
    for _ in range(3):
        key_entry = await fetcher.get_key(token)
        jwt.decode(token, audience=provider.aud, **key_entry)

        client.get_openid_configuration.assert_called_once()
        client.get_jwks.assert_called_once()
