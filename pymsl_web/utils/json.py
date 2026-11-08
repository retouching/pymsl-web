import json

from pymsl_web.utils.messages import message

type JSONValue = bool | int | float | str | list[JSONValue] | dict[str, JSONValue] | None
type JSONObject = dict[str, JSONValue]


def dump(value: JSONValue) -> bytes:
    """Write `value` as compact UTF-8 JSON, its keys in their order."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def load(data: bytes, *, context: str) -> JSONValue:
    """Read one JSON value from `data`; raise ValueError naming `context` for anything else."""
    try:
        value: JSONValue = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError(message(context, "invalid", "JSON expected")) from error
    return value


def load_object(data: bytes, *, context: str) -> JSONObject:
    """Read one JSON object from `data`; raise ValueError naming `context` for anything else."""
    value = load(data, context=context)
    if not isinstance(value, dict):
        raise ValueError(message(context, "invalid", "a JSON object expected"))
    return value


def split_objects(data: bytes, *, context: str) -> list[JSONObject]:
    """Read the run of JSON objects of `data`, glued or separated by whitespace; raise ValueError naming `context`
    for anything else."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(message(context, "invalid", "UTF-8 expected")) from error
    decoder = json.JSONDecoder()
    objects: list[JSONObject] = []
    index = 0
    while True:
        while index < len(text) and text[index].isspace():
            index += 1
        if index == len(text):
            return objects
        try:
            value, index = decoder.raw_decode(text, index)
        except (json.JSONDecodeError, RecursionError) as error:
            raise ValueError(message(context, "invalid", f"JSON expected at {index}")) from error
        if not isinstance(value, dict):
            raise ValueError(message(context, "invalid", f"a JSON object expected at {index}"))
        objects.append(value)
