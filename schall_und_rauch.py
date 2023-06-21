#!/usr/bin/env python3

import ssl
import io
import OpenSSL.crypto as crypto
import socket

import dns
import dns.resolver

from typing import Any, Iterator, Optional, Callable
from functools import partial
from ipaddress import AddressValueError, IPv4Address, IPv4Network,\
    IPv6Address, IPv6Network
from itertools import cycle

from recon_helpers import threaded, run_from_stdin, iter_stdin


def generate_next_nameserver() -> Callable[[], str]:
    nameservers = cycle([
        "8.8.8.8",  # Google
        "8.8.4.4",  # Google
        "1.1.1.1",  # Cloudflare
        "1.0.0.1",  # Cloudflare
        "94.140.14.140",  # AdGuard
        "94.140.14.141",  # AdGuard
        "64.6.64.6",  # Neustar
        "64.6.65.6",  # Neustar
        "156.154.70.1",  # Neustar
        "156.154.71.1",  # Neustar
        "156.154.70.2",  # Neustar
        "156.154.71.2",  # Neustar
        "208.67.222.222",  # OpenDNS
        "208.67.220.220",  # OpenDNS
        "9.9.9.8",  # Quad9
        "9.9.9.9",  # Quad9
        "9.9.9.11",  # Quad9
        "9.9.9.10",  # Quad9
        "77.88.8.1",  # yandex
        "77.88.8.8",  # yandex
        "77.88.8.2",  # yandex
        "185.228.168.9",  # CleanBrowsing
        "185.228.169.9"  # CleanBrowsing
        "193.110.81.0",  # dns0.eu
        "185.253.5.0",  # dns0.eu
        "76.76.2.0",  # Control D
        "76.76.10.0",  # Control D
        "76.223.122.150",  # Alternate DNS
        "94.140.14.14",  # AdGuard DNS
        "94.140.15.15",  # AdGuard DNS
        "212.89.130.180",  # InfoServe GMBH
        "194.25.0.60",  # Deutsche Telekom
        "194.25.0.68",  # Deutsche Telekom
        "176.9.1.117",  # Hetzner
        "195.186.1.111",  # Swisscom
        "195.186.1.110",  # Swisscom
        "195.186.4.110",  # Swisscom
        "64.233.207.16",  # wideopenwest ?
        "8.26.56.26",  # Comodo Secure DNS
        "156.154.70.1",  # UltraDNS
        "156.154.71.1",  # UltraDNS
        "204.194.232.200",  # Cisco OpenDNS
        "204.194.234.200",  # Cisco OpenDNS
        "208.67.220.222",  # Cisco OpenDNS
        "216.146.35.35",  # Norton ConnectSafe ?
        "205.214.45.10",  # MegaPath ?
        "24.113.32.29",  # Wave Broadband
    ])

    def _f() -> str:
        return next(nameservers)

    return _f


next_nameserver = generate_next_nameserver()


def resolve(domain: str, type_: str) -> list[str]:
    resolver = dns.resolver.Resolver(
        filename=io.StringIO(f"nameserver {next_nameserver()}")
    )

    try:
        return [
            d.to_text().split(" ")[-1] for a in
            resolver.resolve(domain, type_, lifetime=.5)
            .response.answer for d in a
        ]
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.exception.Timeout,
        dns.resolver.NoNameservers,
        dns.name.EmptyLabel,
        dns.name.NameTooLong,
        dns.name.LabelTooLong
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
def sni(ip: str) -> tuple[str, list[str]]:
    dst = (ip, 443)
    try:
        cert = ssl.get_server_certificate(dst, timeout=.5).encode()
    except (TimeoutError, ConnectionRefusedError, OSError, BrokenPipeError):
        return ip, []
    x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
    cert_hostname = x509.get_subject().CN

    if cert_hostname:
        return ip, list(cert_hostname.split("\n"))
    else:
        return ip, []


def brute_force_sni(host: str) -> Callable[[str], tuple[str, list[str]]]:
    context = ssl.create_default_context()
    context.set_alpn_protocols(["h2", "http/1.1"])
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    @threaded(40)
    def _f(hostname: str) -> tuple[str, list[str]]:
        try:
            with socket.create_connection((host, 443), timeout=.5) as sock:
                try:
                    with context.wrap_socket(sock, server_hostname=hostname) as _:
                        ...
                except (ssl.SSLCertVerificationError, UnicodeError):
                    return host, []
        except (TimeoutError, ConnectionRefusedError, OSError, BrokenPipeError):
            return host, []

        return host, [hostname]

    return _f


@threaded(40)
def lookup(
    domain: str
) -> tuple[str, list[str]]:
    return domain, resolve(domain, "A") + resolve(domain, "AAAA")


if __name__ == "__main__":
    from sys import argv, stderr, exit as sys_exit

    try:
        cmd = argv[1]
    except IndexError:
        print(
            "subcommand required, choose 'cnames', 'cidr',"
            "\'reverse', 'sni', 'brute-force-sni' or 'lookup'",
            file=stderr
        )

        sys_exit(-1)

    match cmd:
        case "cnames":
            for (k, v) in run_from_stdin(cnames):
                print(f"{k}:{','.join(v)}")
        case "cidr":
            for range in iter_stdin():
                _, ips = unfold_cidr(range)
                print("\n".join(ips))
        case "reverse":
            for (k, v) in run_from_stdin(reverse):
                print(f"{k}:{','.join(v)}")
        case "sni":
            for (k, v) in run_from_stdin(sni):
                print(f"{k}:{','.join(v)}")
        case "brute-force-sni":
            for (k, v) in run_from_stdin(brute_force_sni(argv[2])):
                print(f"{k}:{','.join(v)}")
        case "lookup":
            for (k, v) in run_from_stdin(lookup):
                print(f"{k}:{','.join(v)}")
        case default:
            print("unknown command")
