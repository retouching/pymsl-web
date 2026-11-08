from enum import IntEnum, StrEnum


class CompressionAlgorithm(StrEnum):
    GZIP = "GZIP"
    LZW = "LZW"


class MSLResponseCode(IntEnum):
    FAIL = 1
    TRANSIENT_FAILURE = 2
    ENTITY_REAUTH = 3
    USER_REAUTH = 4
    KEYX_REQUIRED = 5
    ENTITYDATA_REAUTH = 6
    USERDATA_REAUTH = 7
    EXPIRED = 8
    REPLAYED = 9
    SSOTOKEN_REJECTED = 10
