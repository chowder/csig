test:
    uv run ty check .
    uv run ruff check .
    uv run python -m tests.test_sigv4
