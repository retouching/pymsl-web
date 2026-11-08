import json

import pytest

from pymsl_web.crypto.session_keys import SessionKeys
from pymsl_web.exceptions import MSLSessionError
from pymsl_web.messages.header_data import HeaderData
from pymsl_web.session.session import MSLSession
from pymsl_web.tokens.master_token import MasterToken
from tests.unit.support.tokens import Tokens


class TestMSLSessionState:
    @staticmethod
    def document() -> dict[str, object]:
        """Give the JSON document of a started session."""
        session = MSLSession.new("ESN")
        keys = SessionKeys(encryption=bytes(range(16)), hmac=b"\x02" * 32)
        session.start(MasterToken.parse(Tokens.master_token()), keys, HeaderData(message_id=1))
        document: dict[str, object] = session.export().model_dump(mode="json")
        return document

    @pytest.mark.parametrize(
        "change",
        [
            {"message_id": "7"},
            {"extra": 1},
            {"encryption_key": "@@@"},
            {"encryption_key": "AAEC"},
            {"hmac_key": None},
            {"version": 2},
            {"master_token": {"tokendata": "AAAA", "signature": "AA=="}},
        ],
    )
    def test_refuses_malformed(self, change: dict[str, object]) -> None:
        """Raise MSLSessionError, never a raw ValidationError, for a malformed state."""
        with pytest.raises(MSLSessionError, match=r"^Session state: invalid"):
            MSLSession.restore_json(json.dumps({**self.document(), **change}))

    def test_refuses_missing_key(self) -> None:
        """Raise MSLSessionError for a state without its message ID."""
        document = self.document()
        del document["message_id"]
        with pytest.raises(MSLSessionError, match=r"^Session state: invalid"):
            MSLSession.restore_json(json.dumps(document))

    def test_refuses_not_json(self) -> None:
        """Raise MSLSessionError for text that is not JSON."""
        with pytest.raises(MSLSessionError, match=r"^Session state: invalid"):
            MSLSession.restore_json("not json")
