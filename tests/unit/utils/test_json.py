import pytest

from pymsl_web.utils.json import dump, load, load_object, split_objects


class TestJSON:
    def test_dumps_compact(self) -> None:
        """Write JSON without spaces and in the order of the keys."""
        assert dump({"b": 1, "a": [True, None]}) == b'{"b":1,"a":[true,null]}'

    def test_dumps_unicode(self) -> None:
        """Write non-ASCII text as UTF-8, not as escapes."""
        assert dump({"a": "é"}) == '{"a":"é"}'.encode()

    def test_loads_object(self) -> None:
        """Read one JSON object."""
        assert load_object(b'{"a":1}', context="Header") == {"a": 1}

    def test_refuses_non_object(self) -> None:
        """Raise ValueError naming the context for JSON that is not an object."""
        with pytest.raises(ValueError, match=r"^Header: invalid"):
            load_object(b"[1]", context="Header")

    def test_refuses_bad_utf8(self) -> None:
        """Raise ValueError for bytes that are not UTF-8."""
        with pytest.raises(ValueError, match=r"^Header: invalid"):
            load_object(b"\xff", context="Header")

    def test_splits_objects(self) -> None:
        """Split a run of objects glued or separated by whitespace."""
        assert split_objects(b'{"a":1}{"b":2}\n {"c":3}', context="Answer") == [{"a": 1}, {"b": 2}, {"c": 3}]

    def test_refuses_non_object_in_run(self) -> None:
        """Raise ValueError for a value that is not an object."""
        with pytest.raises(ValueError, match=r"^Answer: invalid"):
            split_objects(b'{"a":1}[1]', context="Answer")

    def test_refuses_truncated(self) -> None:
        """Raise ValueError for a truncated object."""
        with pytest.raises(ValueError, match=r"^Answer: invalid"):
            split_objects(b'{"a":1}{"b":', context="Answer")

    def test_splits_empty(self) -> None:
        """Give no object for an empty body."""
        assert split_objects(b" \n", context="Answer") == []

    def test_loads_any_value(self) -> None:
        """Read any JSON value, not only an object."""
        assert load(b'[1,"a",null]', context="Answer") == [1, "a", None]

    def test_refuses_not_json(self) -> None:
        """Raise ValueError naming the context for bytes that are not JSON."""
        with pytest.raises(ValueError, match=r"^Answer: invalid"):
            load(b"echo:", context="Answer")
