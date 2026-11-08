import base64
import json

from pymsl_web.utils.json import JSONObject

type Wire = JSONObject


class Tokens:
    @staticmethod
    def wire(fields: dict[str, object]) -> Wire:
        """Build a token as the server sends it: Base64 of clear JSON and a made-up signature."""
        tokendata = base64.b64encode(json.dumps(fields).encode()).decode()
        return {"tokendata": tokendata, "signature": "AQIDBA=="}

    @staticmethod
    def master_token(
        *, sequence_number: int = 25, serial_number: int = 1, renewal_window: int = 1000, expiration: int = 2000
    ) -> Wire:
        """Build a made-up master token."""
        return Tokens.wire(
            {
                "sessiondata": "AAAA",
                "renewalwindow": renewal_window,
                "serialnumber": serial_number,
                "expiration": expiration,
                "sequencenumber": sequence_number,
            }
        )

    @staticmethod
    def user_id_token(
        *,
        master_token_serial_number: int = 1,
        serial_number: int = 7,
        renewal_window: int = 1000,
        expiration: int = 2000,
        profile_id: str | None = "PROFILE",
    ) -> Wire:
        """Build a made-up user ID token, with the `profileid` the web service adds."""
        fields: dict[str, object] = {
            "userdata": "AAAA",
            "mtserialnumber": master_token_serial_number,
            "renewalwindow": renewal_window,
            "serialnumber": serial_number,
            "expiration": expiration,
        }
        if profile_id is not None:
            fields["profileid"] = profile_id
        return Tokens.wire(fields)

    @staticmethod
    def service_token(
        name: str,
        *,
        data: str = "AAAA",
        master_token_serial_number: int | None = None,
        user_id_token_serial_number: int | None = None,
    ) -> Wire:
        """Build a made-up service token, bound to the serial numbers given."""
        fields: dict[str, object] = {"name": name, "encrypted": True, "servicedata": data}
        if master_token_serial_number is not None:
            fields["mtserialnumber"] = master_token_serial_number
        if user_id_token_serial_number is not None:
            fields["uitserialnumber"] = user_id_token_serial_number
        return Tokens.wire(fields)
