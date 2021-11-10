import requests
import json

from ipaddress import IPv4Network, IPv6Network, AddressValueError, IPv6Address
from functools import partial
from typing import Union, Callable, Iterator, Iterable, Final
from concurrent.futures import ThreadPoolExecutor, as_completed
from sys import argv


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
            ans["data"] for ans in
            json.loads(requests.get(
                f"https://dns.google.com/resolve?name={domain}&type={type_}"
            ).content)["Answer"]
        ]
    except KeyError:
        raise ValueError(f"Could not resolve domain '{domain}'")


def reverse_lookup_ipv4(ip):
    return resolve(f"{'.'.join(ip.split('.')[::-1])}.in-addr.arpa", "PTR")


def reverse_lookup_ipv6(ip):
    resolve(
        f"{'.'.join(IPv6Address(ip).exploded.replace(':', '')[::-1])}.ip6.arpa",
        "PTR"
    )


def resolve_network(
    network: Union[IPv4Network,IPv6Network], resolver: Callable,
    threads: int = 20
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
    ip_range = argv[1]
    if is_ipv4(ip_range):
        generator = resolve_network(IPv4Network(ip_range), reverse_lookup_ipv4)
    elif is_ipv6(ip_range):
        generator = resolve_network(IPv6Network(ip_range), reverse_lookup_ipv6)
    else:
        raise ValueError(f"'{argv[1]}' is not a valid ip range")

    try:
        for res in generator:
            print(res)
    except KeyboardInterrupt:
        print("Interrupted, exiting...")


is_ipv4 = partial(is_ip, type_=IPv4Network)
is_ipv6 = partial(is_ip, type_=IPv6Network)


if __name__ == "__main__":
    main()
