from typing import ClassVar

from pydantic import Field

from pymsl_web.userauth.user_authentication import UserAuthentication
from pymsl_web.utils.json import JSONObject


class NetflixIDUserAuthentication(UserAuthentication):
    scheme: ClassVar[str] = "NETFLIXID"

    netflix_id: str = Field(min_length=1, repr=False)
    secure_netflix_id: str = Field(min_length=1, repr=False)

    def authdata(self) -> JSONObject:
        """Give the `NetflixId` and `SecureNetflixId` cookies of the browser under their wire names."""
        return {"netflixid": self.netflix_id, "securenetflixid": self.secure_netflix_id}
