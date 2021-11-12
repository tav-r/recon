"""
Get SSL common names on port 443 for addresses read from stdin.
"""

import ssl
import json
import functools

import OpenSSL.crypto as crypto

from typing import Iterator, Callable, List, Any


def catch_wrapper(g: Callable, exceptions: List[Any]):
    def _catch_wrapper(f):
        @functools.wraps(f)
        def _wrapped(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except exceptions:
                g()

        return _wrapped

    return _catch_wrapper


def iter_stdin() -> Iterator:
    while True:
        try:
            yield(input())
        except EOFError:
            return


@catch_wrapper(lambda: ..., [ConnectionRefusedError, ConnectionResetError])
def get_cn(ip: str, port: int):
    dst = (ip, 443)
    cert = ssl.get_server_certificate(dst).encode()
    x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
    cert_hostname = x509.get_subject().CN

    for name in cert_hostname.split("\n"):
        yield name


def run_from_iter(iter_: Iterator):
    return [functools.reduce(
        lambda a, b: a + b,
        get_cn(line.strip(), 443)
    ) for line in iter_]


def run_from_stdin():
    return run_from_iter(iter_stdin())


if __name__ == "__main__":
    print(json.dumps(run_from_stdin()))
