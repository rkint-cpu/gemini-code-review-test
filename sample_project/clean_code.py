def greet_user(name: str) -> str:
    cleaned = name.strip()
    if not cleaned:
        return "Hello, Guest!"
    return f"Hello, {cleaned}!"