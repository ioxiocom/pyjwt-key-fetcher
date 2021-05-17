import jwt
import pytest


@pytest.mark.asyncio
async def test_fetching_key(create_provider_fetcher_and_client):
    provider, fetcher, client = await create_provider_fetcher_and_client()

    token = provider.create_token()
    key_entry = await fetcher.get_key_from_token(token)
    jwt.decode(token, audience=provider.aud, **key_entry)
