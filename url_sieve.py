from urllib.parse import urlparse, ParseResult, urlunparse
from typing import Iterator, List, Dict, overload
from abc import ABCMeta, abstractmethod
import enum

class ParamKind(enum.Enum):
    KeyValue: int = 1
    Constant: int = 2

class URLParam(metaclass=ABCMeta):
    """ABC implemented by KeyValueParam and ConstParam."""

    @abstractmethod
    def __str__(self):
        ...

    @abstractmethod
    def __eq__(self, other):
        ...

    @property
    def kind(self) -> ParamKind:
        return self._kind

class KeyValueParam(URLParam):
    """
    Class to represent a constent parameter (i.e. one with an '=')
    """

    def __init__(self, key: str, value: str):
        self.__key = key
        self.__value = value
        self._kind = ParamKind.KeyValue

    @property
    def key(self) -> str:
        return self.__key

    def __str__(self):
        return f"{self.__key}={self.__value}"

    def __eq__(self, other):
        if other.kind == self.kind and other.key == self.__key:
            return True

        return False


class ConstParam(URLParam):
    """
    Class to represent a constent parameter (i.e. one without an '=')
    """

    def __init__(self, const: str):
        self.__const = const
        self._kind = ParamKind.Constant

    @property
    def const(self) -> str:
        return self.__const

    def __str__(self):
        return self.__const

    def __eq__(self, other):
        if other.kind == self.kind and other.const == self.__const:
            return True

        return False


def get_queries(url: ParseResult) -> List[URLParam]:
    """
    Take a parse url and parse its queries.

    Args:
        url (ParseResult): URL to extract queries from
    
    Returns:
        List[URLParam]: list of parsed parameters
    """

    def _f() -> Iterator:
        for p in url.query.split("&"):
            if "=" in p: yield KeyValueParam(*p.split("=", 1))
            else: yield ConstParam(p) 

    return [query for query in _f()]


class URLDatabase:
    """
    Class to store URLs.

    Example:
    >>> url_db = URLDatabase()
    >>> url_db.update(urlparse("http://google.com/?q=test"))
    >>> url_db.update(urlparse("http://google.com/?r=something"))
    >>> url_db.update(urlparse("https://example.com/"))
    >>> url_db.update(urlparse("http://google.com/?q=something&r=or&s=else"))
    >>> list(url_db)
    ['http://google.com/?q=test&r=something&s=else', 'https://example.com/']
    """

    def __init__(self):
        self.__urls: Dict[str, URLParam] = dict()

    def update(self, url: ParseResult):
        """
        Update the 'database', i.e. add a URL if it is unknown, add queries
        to a URL if the URL is known but the query is not or do nothing.

        Args:
            url (ParseResult): URL to update the database with
        """

        new_queries = get_queries(url)
        url_base_str = f"{url.scheme}://{url.netloc}{url.path}"

        if url_base_str not in self.__urls:
            self.__urls.update({url_base_str: new_queries})
            return

        for q in new_queries:
            if q not in self.__urls[url_base_str]:
                self.__urls[url_base_str].append(q)

    def __iter__(self) -> Iterator[str]:
        for u in self.__urls.keys():
            params = "&".join(str(p) for p in self.__urls[u])
            yield f"{u}?{params}" if params else u


def main():
    known_urls = URLDatabase()

    while True:
        try:
            line = input()
        except EOFError:
            break

        url = urlparse(line)

        if not url.netloc or not url.scheme:
            continue
        
        known_urls.update(url)

    for url in known_urls:
        print(url)

if __name__ == "__main__":
    from os import environ
    from doctest import testmod

    if "DOCTEST" in environ:
        testmod()
    else:
        main()