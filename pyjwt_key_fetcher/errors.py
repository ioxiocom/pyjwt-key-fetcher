class JWTKeyFetcherError(Exception):
    """Base class for JWTKeyFetcher errors"""


class JWTFormatError(JWTKeyFetcherError):
    """Raised for keys that do not contain all kind of expected values"""


class JWTHTTPFetchError(JWTKeyFetcherError):
    """Raised if there's a problem doing http(s) requests"""


class JWTOpenIDConnectError(JWTKeyFetcherError):
    """Raised if expectations for OpenID Connect fields fail"""
