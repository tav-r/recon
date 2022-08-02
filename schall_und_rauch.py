import functools
import json
import fileinput
import ssl
import OpenSSL.crypto as crypto

import dns
import dns.resolver

from typing import Any, Iterator, Optional, Callable, Iterable, TypeVar
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from functools import partial, reduce
from ipaddress import AddressValueError, IPv4Address, IPv4Network,\
    IPv6Address, IPv6Network


RT = TypeVar("RT")


def threaded(nthreads: int) -> Callable[
    [Callable[..., Any]], Callable[..., Any]
]:
    def _g(f: Callable[..., Any]) -> Callable[..., Any]:
        pool = ThreadPoolExecutor(nthreads)

        @functools.wraps(f)
        def _f(*args: list[Any], **kwargs: dict[str, Any]) -> Future[RT]:
            return pool.submit(f, *args, **kwargs)

        return _f
    return _g


def resolve(domain: str, type_: str) -> list[str]:
    try:
        return [
            d.to_text().split(" ")[-1] for a in
            dns.resolver.resolve(domain, type_)
            .response.answer for d in a
        ]
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.exception.Timeout,
        dns.resolver.NoNameservers,
        dns.name.EmptyLabel
    ):
        return []


@threaded(40)
def cnames(domain: str) -> tuple[Optional[str], list[str]]:
    def _f(domain: str) -> list[str]:
        res = resolve(domain, "CNAME")

        return res + [c for d in res for c in _f(d) if c not in res]

    return domain, _f(domain)


def reverse_lookup_ipv4(ip: str) -> tuple[str, list[str]]:
    return ip, resolve(f"{'.'.join(ip.split('.')[::-1])}.in-addr.arpa", "PTR")


def reverse_lookup_ipv6(ip: str) -> tuple[str, list[str]]:
    parsed_ip = IPv6Address(ip)
    return ip, resolve(
        f"{'.'.join(parsed_ip.exploded.replace(':', '')[::-1])}.ip6.arpa",
        "PTR"
    )


def run_from_iter(
    f: Callable[[str], Future[tuple[str, list[str]]]],
    iter_: Iterable,
) -> dict[str, list[str]]:
    return dict(
        filter(
            lambda x: x[1],
            (c.result() for c in as_completed(
                f(name) for name in iter_
            ) if not c.exception())
        )
    )


def run_from_stdin(
    f: Callable[[str], Future[tuple[str, list[str]]]]
) -> dict[str, list[str]]:
    try:
        with fileinput.input() as file_input:
            res = run_from_iter(
                f,
                [n.strip() for n in file_input if n.strip()]
            )

    except KeyboardInterrupt:
        print("Interrupted, exiting...")

    return res


def is_ip(address: str, type_: Callable) -> bool:
    try:
        type_(address)
    except AddressValueError:
        return False
    return True


is_ipv4 = partial(is_ip, type_=IPv4Address)
is_ipv6 = partial(is_ip, type_=IPv6Address)
is_ipv4_range = partial(is_ip, type_=IPv4Network)
is_ipv6_range = partial(is_ip, type_=IPv6Network)


@threaded(40)
def reverse(
    ip: str
) -> tuple[str, list[str]]:
    if is_ipv4(ip):
        resolver = reverse_lookup_ipv4

    elif is_ipv6(ip):
        resolver = reverse_lookup_ipv6

    else:
        return ip, []

    return resolver(ip)


@threaded(1)
def unfold_cidr(range: str) -> tuple[str, list[str]]:
    gen: Callable[..., Iterator[Any]]

    if is_ipv4_range(range):
        gen = IPv4Network(range).hosts
    elif is_ipv6_range(range):
        gen = IPv6Network(range).hosts
    else:
        return range, []

    return range, list(str(i) for i in gen())


@threaded(40)
def get_cn(ip: str) -> tuple[str, list[str]]:
    dst = (ip, 443)
    cert = ssl.get_server_certificate(dst, timeout=.5).encode()
    x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
    cert_hostname = x509.get_subject().CN

    return ip, list(cert_hostname.split("\n"))


if __name__ == "__main__":
    from sys import argv

    cmd = argv[1]
    del(argv[1])

    match cmd:
        case "cnames":
            print(json.dumps(run_from_stdin(cnames), indent=4))
        case "cidr":
            print("\n".join(reduce(
                lambda x, y: list(x) + list(y),
                (a for a in run_from_stdin(unfold_cidr).values())
            )))
        case "reverse":
            print(json.dumps(run_from_stdin(reverse), indent=4))
        case "sni":
            print(json.dumps(run_from_stdin(get_cn), indent=4))
