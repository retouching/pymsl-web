from pymsl_web.utils.messages import message


class TestMessage:
    def test_writes_causes(self) -> None:
        """Write the subject, the outcome and the causes, without the empty ones."""
        assert message("Answer", "invalid", "header", "") == "Answer: invalid (header)"

    def test_writes_no_parentheses(self) -> None:
        """Leave the parentheses out without a cause."""
        assert message("Answer", "empty") == "Answer: empty"
