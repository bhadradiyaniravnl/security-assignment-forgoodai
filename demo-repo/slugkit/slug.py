"""URL slug generation."""
import re
import unicodedata


def slugify(text: str, max_length: int = 50) -> str:
    """Turn arbitrary text into a lowercase, hyphen-separated URL slug.

    >>> slugify("Hello, World!")
    'hello-world'
    """
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    text = re.sub(r"[^\w\s-]", "", text).strip()
    text = re.sub(r"[\s_]+", "-", text)
    return text[:max_length]
