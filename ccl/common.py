from re import Pattern
from typing import Union
from collections.abc import Collection, Callable


KeySearch = Union[str, Pattern, Collection[str], Callable[[str], bool]]


def is_keysearch_hit(search: KeySearch, value: str):
    if isinstance(search, str):
        return value == search
    elif isinstance(search, Pattern):
        return search.search(value) is not None
    elif isinstance(search, Collection):
        return value in set(search)
    elif isinstance(search, Callable):
        return search(value)
    else:
        raise TypeError(f"Unexpected type: {type(search)} (expects: {KeySearch})")