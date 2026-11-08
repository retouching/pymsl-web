def message(subject: str, outcome: str, *causes: str) -> str:
    """Write `<Subject>: <outcome> (<causes>)`, without the parentheses when every cause is empty.

    `message("Answer", "invalid", "header")` writes `Answer: invalid (header)`.
    """
    parts = [cause for cause in causes if cause]
    return f"{subject}: {outcome}" + (f" ({', '.join(parts)})" if parts else "")
