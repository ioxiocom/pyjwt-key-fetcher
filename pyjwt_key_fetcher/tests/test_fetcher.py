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
async def test_fetching_same_kid_only_once(create_provider_fetcher_and_client):
    provider, fetcher, client = await create_provider_fetcher_and_client()

    tokens = {provider.create_token() for _ in range(3)}
    for _ in range(2):
        for token in tokens:
            key_entry = await fetcher.get_key(token)
            jwt.decode(token, audience=provider.aud, **key_entry)

            client.get_openid_configuration.assert_called_once()
            client.get_jwks.assert_called_once()


@pytest.mark.asyncio
async def test_fetching_after_issuing_new_key(create_provider_fetcher_and_client):
    provider, fetcher, client = await create_provider_fetcher_and_client()

    # Create first token and validate it
    token = provider.create_token()
    key_entry = await fetcher.get_key(token)
    jwt.decode(token, audience=provider.aud, **key_entry)

    client.get_openid_configuration.assert_called_once()
    client.get_jwks.assert_called_once()

    # Make the provider roll out a new key
    provider.generate_new_key()

    # Get a new token, signed with the new key
    token_2 = provider.create_token()
    assert fetcher.get_kid(token) != fetcher.get_kid(token_2)

    # Check the new token can be verified
    key_entry_2 = await fetcher.get_key(token_2)
    jwt.decode(token_2, audience=provider.aud, **key_entry_2)

    # Check the old token can be verified as well
    key_entry = await fetcher.get_key(token)
    jwt.decode(token, audience=provider.aud, **key_entry)

    # Verify we've fetched config and JWKs only twice (once per "kid")
    assert client.get_openid_configuration.call_count == 2
    assert client.get_jwks.call_count == 2
