from typing import Final

import pymsl_web

PUBLIC_NAMES: Final = (
    "AsymmetricWrappedKeyExchange",
    "CompressionAlgorithm",
    "EntityAuthentication",
    "KeyExchange",
    "MSLClient",
    "MSLConfiguration",
    "MSLCryptoError",
    "MSLError",
    "MSLMessageError",
    "MSLResponseCode",
    "MSLSession",
    "MSLSessionError",
    "MSLSessionState",
    "MSLTransportError",
    "NetflixIDUserAuthentication",
    "NoneEntityAuthentication",
    "PyMSLError",
    "UserAuthentication",
)


class TestPublicAPI:
    def test_exports(self) -> None:
        """Export the names of the public API alone."""
        assert sorted(pymsl_web.__all__) == sorted(PUBLIC_NAMES)

    def test_imports(self) -> None:
        """Give each exported name from the package itself."""
        assert all(hasattr(pymsl_web, name) for name in PUBLIC_NAMES)
