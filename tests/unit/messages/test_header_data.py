import pytest

from pymsl_web.exceptions import MSLMessageError
from pymsl_web.messages.capabilities import MessageCapabilities
from pymsl_web.messages.header_data import HeaderData
from pymsl_web.utils.json import JSONObject
from tests.unit.support.tokens import Tokens

CAPABILITIES = MessageCapabilities(compression_algorithms=("GZIP",), languages=(), encoder_formats=("JSON",))


class TestHeaderData:
    def test_writes_owner_order(self) -> None:
        """Write the fields in the order of the owner's `_build_header_payload`, the key request in a list."""
        header = HeaderData(
            message_id=7,
            renewable=True,
            handshake=True,
            capabilities=CAPABILITIES,
            timestamp=100,
            sender="ESN",
            key_request={"scheme": "ASYMMETRIC_WRAPPED", "keydata": {}},
        )
        wire = header.to_wire()
        assert list(wire) == [
            "messageid",
            "renewable",
            "handshake",
            "capabilities",
            "timestamp",
            "sender",
            "nonreplayable",
            "keyrequestdata",
        ]
        assert wire["keyrequestdata"] == [{"scheme": "ASYMMETRIC_WRAPPED", "keydata": {}}]
        assert wire["nonreplayable"] is False

    def test_writes_user_and_tokens(self) -> None:
        """Write the user authentication, the user ID token and the service tokens after the other fields."""
        header = HeaderData(
            message_id=7,
            renewable=True,
            handshake=False,
            capabilities=CAPABILITIES,
            timestamp=100,
            sender="ESN",
            user_authentication={"scheme": "NETFLIXID", "authdata": {}},
            user_id_token=Tokens.user_id_token(),
            service_tokens=[Tokens.service_token("sf")],
        )
        assert list(header.to_wire())[-3:] == ["userauthdata", "useridtoken", "servicetokens"]

    def test_reads_browser_answer(self) -> None:
        """Read a header shaped like the web player's answer."""
        header = HeaderData.parse(
            {
                "servicetokens": [Tokens.service_token("cad")],
                "useridtoken": Tokens.user_id_token(),
                "handshake": False,
                "capabilities": {"languages": [], "compressionalgos": ["LZW"], "maxpayloadchunksize": -1},
                "sender": "Netflix",
                "renewable": False,
                "messageid": 5491718558033173,
                "timestamp": 1770838600,
            }
        )
        assert header.message_id == 5491718558033173
        assert header.sender == "Netflix"
        assert header.timestamp == 1770838600
        assert header.user_id_token == Tokens.user_id_token()
        assert len(header.service_tokens) == 1

    def test_reads_key_response(self) -> None:
        """Read the key response of a handshake answer."""
        response: JSONObject = {"scheme": "ASYMMETRIC_WRAPPED", "mastertoken": Tokens.master_token(), "keydata": {}}
        assert HeaderData.parse({"messageid": 1, "keyresponsedata": response}).key_response == response

    def test_refuses_missing_message_id(self) -> None:
        """Raise MSLMessageError for a header without its message ID."""
        with pytest.raises(MSLMessageError, match=r"^Header: invalid"):
            HeaderData.parse({"renewable": True})

    def test_refuses_wrong_type(self) -> None:
        """Raise MSLMessageError for a field of the wrong type."""
        with pytest.raises(MSLMessageError, match=r"^Header: invalid"):
            HeaderData.parse({"messageid": 1, "servicetokens": {}})
