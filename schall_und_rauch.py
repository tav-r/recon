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
        "9.9.9.9",  # Quad9
        "9.9.9.11",  # Quad9
        "77.88.8.1",  # yandex
        "77.88.8.8",  # yandex
        "77.88.8.2",  # yandex
        "185.228.168.9",  # CleanBrowsing
        "185.228.169.9"  # CleanBrowsing
        "193.110.81.0",  # dns0.eu
        "185.253.5.0",  # dns0.eu
        "76.76.2.0",  # Control D
        "76.76.10.0",  # Control D
        "94.140.14.14",  # AdGuard DNS
        "94.140.15.15",  # AdGuard DNS
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


def resolve(
        domain: str,
        type_: str,
        nameserver_f: Callable[[], str] = next_nameserver
) -> list[str]:
    return resolve_with(nameserver_f())(domain, type_)


def resolve_with(ns: str) -> Callable[[str, str], list[str]]:
    def _resolve(domain: str, type_: str) -> list[str]:
        resolver = dns.resolver.Resolver(
            filename=io.StringIO(f"nameserver {ns}")  # type: ignore
        )

        try:
            return [
                d.to_text().split(" ")[-1] for a in  # type: ignore
                resolver.resolve(domain, type_, lifetime=.5)  # type: ignore
                .response.answer for d in a  # type: ignore
            ]
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.exception.Timeout,  # type: ignore
            dns.resolver.NoNameservers,
            dns.name.EmptyLabel,  # type: ignore
            dns.name.NameTooLong,  # type: ignore
            dns.name.LabelTooLong  # type: ignore
        ):
            return []

    return _resolve


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


def is_ip(address: str, type_: Callable[[str], Any]) -> bool:
    try:
        type_(address)
    except AddressValueError:
        return False
    return True


is_ipv4 = partial(is_ip, type_=IPv4Address)
is_ipv6 = partial(is_ip, type_=IPv6Address)
is_ipv4_range = partial(is_ip, type_=IPv4Network)
is_ipv6_range = partial(is_ip, type_=IPv6Network)


@threaded(100)
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

    return gen()


@threaded(500)
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


def _try_sni(host: str, hostname: str, context: ssl.SSLContext | None) -> tuple[str, list[str]]:
    assert context

    try:
        with socket.create_connection((host, 443), timeout=2) as sock:
            try:
                with context.wrap_socket(sock, server_hostname=hostname) as s:
                    peercert = s.getpeercert()
                    if not peercert:
                        return host, []

                    alt_names = [b for (_, b) in peercert["subjectAltName"] if s.getpeercert()]
                    subject_names = [v for ((k, v),) in peercert["subject"] if k == "commonName"]  # type: ignore
                    names = alt_names + subject_names
                        

                    if hostname in names:
                        return host, [hostname]
            except:
                ...
    except (TimeoutError, ConnectionRefusedError, OSError, BrokenPipeError, UnicodeError) as _:
        ...

    return host, []


def inject_context(f: Callable[..., Any]) -> Callable[..., Any]:
    context = ssl.create_default_context()
    context.set_alpn_protocols(["h2", "http/1.1"])
    context.check_hostname = False
    context.verify_mode = ssl.CERT_OPTIONAL

    return partial(f, context=context)

@inject_context
def brute_force_sni(
    host: str,
    context: ssl.SSLContext | None = None
) -> Callable[[str], tuple[str, list[str]]]:
    return threaded(40)(lambda hostname: _try_sni(host, hostname, context))

@inject_context
def brute_force_sni_rev(
    hostname_f: Callable[[str], str], context: ssl.SSLContext | None = None
) -> Callable[[str], tuple[str, list[str]]]:
    return threaded(40)(
        lambda host: _try_sni(host, hostname_f(host), context)
    )

@threaded(40)
def lookup(
    domain: str,
    nameserver_f: Callable[[], str] | None = None
) -> tuple[str, list[str]]:
    if nameserver_f:
        return domain, resolve(domain, "A", nameserver_f)\
            + resolve(domain, "AAAA", nameserver_f)
    else:
        return domain, resolve(domain, "A") + resolve(domain, "AAAA")


def print_help() -> None:
    print(
        "valid subcommands: 'cnames', 'cidr', 'reverse', 'sni'"
        "'brute-force-sni', 'query nameservers'  or 'lookup'",
        file=stderr
    )

if __name__ == "__main__":
    from sys import argv, stderr, exit as sys_exit

    try:
        cmd = argv[1]
    except IndexError:
        print_help()

        sys_exit(-1)

    match cmd:
        case "cnames":
            for (k, v) in run_from_stdin(cnames):
                print(f"{k}:{','.join(v)}")
        case "cidr":
            for range in iter_stdin():
                for host in unfold_cidr(range):
                    print(str(host))
        case "reverse":
            for (k, v) in run_from_stdin(reverse):
                print(f"{k}:{','.join(v)}")
        case "sni":
            for (k, v) in run_from_stdin(sni):
                print(f"{k}:{','.join(v)}")
        case "brute-force-sni":
            target = [a for a in argv[2:] if not a.startswith("-")][0]
            # prepend target to hostname if -m is passed
            if "-m" in argv:
                hostname_f: Callable[[str], str] =\
                    lambda s: f"{s}{'' if s.endswith('.') else '.'}{target}"
            else:
                hostname_f: Callable[[str], str] = lambda _: target

            # read lists of hosts to scan for given hostname from stdin
            # if -r is passed
            if "-r" in argv:
                f = brute_force_sni_rev(hostname_f)
            # otherwise read hostnames from stdin and scan a single host
            else:
                f = brute_force_sni(target)

            for (k, v) in run_from_stdin(f):
                print(f"{k}:{','.join(v)}")
        case "lookup":
            # if -l is passed, read nameservers from file
            f = lookup
            if "-l" in argv:
                with open(argv[argv.index("-l") + 1], "r") as f:
                    ns_list = [l.strip() for l in f.readlines()]
                    nameserver_f = cycle(ns_list).__next__
                    f = partial(lookup, nameserver_f=nameserver_f)

            for (k, v) in run_from_stdin(f):
                print(f"{k}:{','.join(v)}")
        case "query-nameservers":
            domain = argv[2]
            f = threaded(40)(lambda ns: (
                ns,
                resolve_with(ns)(domain, "A") +
                resolve_with(ns)(domain, "AAAA")
            ))
            for (k, v) in run_from_stdin(f):
                print(f"{k}:{','.join(v)}")
        case default:
            print("[error] unknown command")
            print_help()
