import json

import dns
import dns.resolver

from argparse import ArgumentParser
from ipaddress import IPv4Network, IPv6Network, AddressValueError, IPv6Address
from functools import partial
from typing import Union, Callable, Iterator, Iterable, Final
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import chain


def iter_stdin() -> Iterator:
    while True:
        try:
            yield input()
        except EOFError:
            return


def chunked_iterator(i: Iterable, chunk_size: int) -> Iterator:
    buffer = []
    for n, v in enumerate(i, 1):
        buffer.append(v)
        if not n % chunk_size:
            yield buffer
            buffer =[]


def is_ip(address: str, type_: Callable):
    try:
        type_(address)
    except AddressValueError:
        return False
    return True


def resolve(domain: str, type_: str):
    try:
        return [
            d.to_text().split(" ")[-1] for a in
            dns.resolver.resolve(domain, type_, lifetime=2)
            .response.answer for d in a
        ]
    except (
        dns.resolver.NXDOMAIN,
        dns.exception.Timeout,
        dns.resolver.NoNameservers
    ):
        raise ValueError(f"Could not resolve domain '{domain}'")


def reverse_lookup_ipv4(ip):
    return ip, resolve(f"{'.'.join(ip.split('.')[::-1])}.in-addr.arpa", "PTR")


def reverse_lookup_ipv6(ip):
    return ip, resolve(
        f"{'.'.join(IPv6Address(ip).exploded.replace(':', '')[::-1])}.ip6.arpa",
        "PTR"
    )


def pick_ipv(ip_range):
    if is_ipv4(ip_range):
        return IPv4Network(ip_range), reverse_lookup_ipv4
    elif is_ipv6(ip_range):
        return IPv6Network(ip_range), reverse_lookup_ipv6
    else:
        raise ValueError(f"'{ip_range}' is not a valid ip range")


def resolve_network(
    network: Union[IPv4Network, IPv6Network], resolver: Callable,
    threads: int = 10
) -> Iterator:
    executor: Final = ThreadPoolExecutor(threads)

    for addrs in chunked_iterator(network.hosts(), threads):
        tasks = [executor.submit(resolver, str(addr)) for addr in addrs]

        for res in as_completed(tasks):
            try:
                yield res.result()
            except ValueError:
                continue


def main():
    ap = ArgumentParser()
    ap.add_argument(
        "-t", "--threads", dest="threads", default=10,
        help="Number of parallel DNS resolver threads",
        type=int
    )

    args = ap.parse_args()

    generator = chain(*(
        resolve_network(*pick_ipv(ip_range), threads=args.threads)
        for ip_range in iter_stdin()
    ))

    try:
        print(json.dumps(
            dict(res for res in generator),
            indent=4
        ))
    except KeyboardInterrupt:
        print("Interrupted, exiting...")


is_ipv4 = partial(is_ip, type_=IPv4Network)
is_ipv6 = partial(is_ip, type_=IPv6Network)


if __name__ == "__main__":
    main()
