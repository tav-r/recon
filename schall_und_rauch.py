#!/usr/bin/env python3

import asyncio
import socket
import ssl
from functools import partial
from ipaddress import AddressValueError, IPv4Address, IPv4Network, IPv6Address, IPv6Network
from itertools import cycle
from random import sample
from sys import stdin,stderr
from typing import Any, Awaitable, Callable, Iterator, Optional

from dnslib import DNSRecord  # type: ignore


def iter_stdin() -> Iterator[str]:
    while line := stdin.readline():
        yield line.strip()


def generate_next_nameserver() -> Callable[[], str]:
    nameservers = [
        "50.234.132.241",
        "210.94.0.7",
        "76.76.10.1",
        "185.43.135.1",
        "176.9.1.117",
        "210.87.253.60",
        "162.159.36.46",
        "46.147.193.104",
        "151.203.0.85",
        "194.150.168.169",
        "208.91.112.52",
        "211.115.194.1",
        "195.208.5.1",
        "162.159.46.90",
        "84.54.64.35",
        "172.64.36.103",
        "101.102.103.104",
        "159.69.114.157",
        "1.0.0.3",
        "77.88.8.1",
        "194.25.0.60",
        "162.159.50.27",
        "99.99.99.193",
        "23.95.234.28",
        "205.171.202.166",
        "162.159.56.75",
        "92.60.50.40",
        "198.153.192.50",
        "198.54.117.11",
        "5.11.11.11",
        "193.42.159.2",
        "94.140.14.141",
        "162.159.36.158",
        "94.247.43.254",
        "151.197.0.38",
        "162.159.46.28",
        "172.64.36.102",
        "151.196.0.38",
        "94.140.14.14",
        "162.159.36.252",
        "162.159.36.96",
        "151.202.0.85",
        "45.90.30.226",
        "156.154.70.8",
        "162.159.46.117",
        "76.76.10.5",
        "195.10.195.195",
        "190.93.189.30",
        "195.140.195.21",
        "2.56.220.2",
        "209.244.0.4",
        "87.244.9.194",
        "151.201.0.39",
        "92.43.224.1",
        "8.8.8.8",
        "80.78.132.79",
        "151.198.0.39",
        "156.154.71.1",
        "94.140.15.15",
        "96.69.146.137",
        "9.9.9.9",
        "95.158.129.2",
        "141.1.1.1",
        "221.139.13.130",
        "45.90.30.169",
        "213.211.50.2",
        "76.76.2.0",
        "192.71.166.92",
        "1.1.1.2",
        "151.201.0.38",
        "202.248.37.74",
        "64.132.94.250",
        "194.102.126.11",
        "45.90.30.129",
        "1.1.1.3",
        "76.76.2.5",
        "206.253.33.130",
        "198.153.194.50",
        "31.3.135.232",
        "45.90.30.126",
        "165.246.10.2",
        "45.90.28.193",
        "121.139.218.165",
        "212.12.14.122",
        "95.85.95.85",
        "76.76.10.0",
        "212.113.0.3",
        "162.159.36.185",
        "76.76.2.4",
        "162.159.46.51",
        "162.159.36.227",
        "62.82.138.5",
        "162.159.36.86",
        "141.154.0.68",
        "199.85.127.10",
        "202.46.34.74",
        "64.9.50.67",
        "12.51.21.245",
        "193.202.121.50",
        "91.144.22.198",
        "211.115.194.3",
        "134.75.122.2",
        "203.248.252.2",
        "162.159.46.177",
        "117.103.228.101",
        "162.159.46.18",
        "172.64.36.0",
        "193.238.77.62",
        "208.72.160.67",
        "162.159.46.147",
        "190.11.225.2",
        "35.155.221.215",
        "162.159.46.8",
        "66.163.0.161",
        "8.20.247.20",
        "50.235.228.46",
        "218.146.255.235",
        "216.136.95.2",
        "156.154.70.22",
        "24.104.140.255",
        "207.68.32.39",
        "76.76.10.4",
        "41.221.192.167",
        "188.225.225.25",
        "88.208.244.225",
        "45.90.28.126",
        "149.112.112.10",
        "202.78.97.41",
        "193.226.61.1",
        "216.170.153.146",
        "45.90.28.189",
        "156.154.70.7",
        "151.199.0.39",
        "9.9.9.12",
        "162.159.46.1",
        "95.143.220.5",
        "162.159.36.64",
        "4.2.2.2",
        "185.74.5.5",
        "151.203.0.84",
        "162.159.36.181",
        "149.112.122.20",
        "199.85.126.20",
        "64.6.65.6",
        "76.76.10.2",
        "208.67.220.220",
        "62.76.62.76",
        "54.94.175.250",
        "217.150.35.129",
        "9.9.9.11",
        "209.239.11.98",
        "52.3.100.184",
        "212.211.132.4",
        "193.238.77.61",
        "50.237.34.1",
        "210.87.250.155",
        "151.196.0.37",
        "198.153.192.40",
        "81.3.27.54",
        "211.115.194.4",
        "209.130.136.2",
        "85.9.129.38",
        "156.154.71.2",
        "164.124.107.9",
        "66.28.0.61",
        "216.146.36.36",
        "149.112.112.11",
        "193.2.246.9",
        "177.184.176.5",
        "162.159.46.197",
        "77.88.8.8",
        "216.165.129.157",
        "193.58.251.251",
        "168.95.1.1",
        "5.1.66.255",
        "77.88.8.88",
        "165.87.13.129",
        "156.154.70.10",
        "45.90.28.169",
        "162.159.46.214",
        "193.227.50.3",
        "45.90.28.250",
        "192.133.129.2",
        "45.90.30.193",
        "66.163.0.173",
        "51.154.127.161",
        "77.88.8.3",
        "46.231.32.23",
        "210.94.0.73",
        "162.159.46.172",
        "4.2.2.5",
        "204.95.160.2",
        "8.20.247.10",
        "64.6.64.6",
        "202.30.143.11",
        "92.222.117.114",
        "195.27.1.1",
        "12.127.17.72",
        "107.0.218.126",
        "196.3.132.154",
    ]

    ns_gen = cycle(sample(nameservers, len(nameservers)))

    def _f() -> str:
        return next(ns_gen)

    return _f


next_nameserver = generate_next_nameserver()


async def resolve(host: str, qtype: str = "A", server: str = "8.8.8.8"):
    query = DNSRecord.question(host, qtype).pack()
    addr = (server, 53)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)

    loop = asyncio.get_running_loop()
    future = loop.create_future()

    def on_readable():
        try:
            data, _ = sock.recvfrom(512)
            if not future.done():
                future.set_result(data)
        except Exception as e:
            if not future.done():
                future.set_exception(e)
        finally:
            loop.remove_reader(sock.fileno())

    try:
        loop.add_reader(sock.fileno(), on_readable)

        sock.sendto(query, addr)

        raw_data = await asyncio.wait_for(future, timeout=2.0)
        return [str(rr.rdata) for rr in DNSRecord.parse(raw_data).rr]
        
    except asyncio.TimeoutError:
        loop.remove_reader(sock.fileno())
        raise
    finally:
        sock.close()


async def cnames(domain: str, nameserver_f: Callable[[], str]) -> tuple[Optional[str], list[str]]:
    async def _f(domain: str) -> list[str]:
        res = await resolve(domain, "CNAME", nameserver_f())

        return res + [c for d in res for c in await _f(d) if c not in res]

    return domain, await _f(domain)


async def reverse_lookup_ipv4(ip: str, nameserver_f: Callable[[], str]) -> tuple[str, list[str]]:
    return ip, await resolve(f"{'.'.join(ip.split('.')[::-1])}.in-addr.arpa", "PTR", nameserver_f())


async def reverse_lookup_ipv6(ip: str,  nameserver_f: Callable[[], str]) -> tuple[str, list[str]]:
    rev_ptr = IPv6Address(ip).reverse_pointer
    return ip, await resolve(
        rev_ptr,
        "PTR",
        nameserver_f()
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


async def reverse(
    ip: str,
    nameserver_f: Callable[[], str]
) -> tuple[Optional[str], list[str]]:
    if is_ipv4(ip):
        resolver = reverse_lookup_ipv4

    elif is_ipv6(ip):
        resolver = reverse_lookup_ipv6

    else:
        return ip, []

    return await resolver(ip, nameserver_f)


def unfold_cidr(ip_range: str) -> Iterator[str]:
    gen: Callable[..., Iterator[Any]]

    if is_ipv4_range(ip_range):
        gen = IPv4Network(ip_range).hosts
    elif is_ipv6_range(ip_range):
        gen = IPv6Network(ip_range).hosts
    else:
        gen = iter([])  # type: ignore

    return (str(a) for a in gen())


async def extract_from_cert(ip: str) -> tuple[Optional[str], list[str]]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED # Library parses it for us

    names: set[str] = set()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, 443, ssl=context),
            timeout=1.0
        )
        cert = writer.get_extra_info('ssl_object').getpeercert()
        
        # cert is now a dict; extract Subject Alternative Names
        if 'subjectAltName' in cert:
            names.update(str(x[1]) for x in cert['subjectAltName'])
            
        # Extract Common Name
        for rdn in cert.get('subject', []):
            for attr in rdn:
                if attr[0] == 'commonName':
                    names.add(str(attr[1]))

        writer.close()
        await writer.wait_closed()
    except Exception:
        pass
        
    return ip, list(names)

async def lookup(
    domain: str,
    nameserver_f: Callable[[], str]
) -> tuple[Optional[str], list[str]]:
    return domain, (await resolve(domain, "A", nameserver_f()))\
        + (await resolve(domain, "AAAA", nameserver_f()))


def print_help() -> None:
    print(
        "valid subcommands: 'cnames', 'cidr', 'reverse', "
        "'cert', 'query nameservers'  or 'lookup'",
        file=stderr
    )

async def main(cmd: str) -> None:
    async def run_template(f: Callable[..., Awaitable[tuple[Optional[str], list[str]]]], inputs: Iterator[str], parallel: int) -> None:
        pending: set[asyncio.Task] = set()

        for _ in range(parallel):
            try:
                item = next(inputs)
                pending.add(asyncio.create_task(f(item.strip())))  # type: ignore
            except StopIteration:
                break

        while pending:
            done, pending = await asyncio.wait(
                pending, 
                return_when=asyncio.FIRST_COMPLETED
            )

            for task in done:
                try:
                    (k, v) = task.result()

                    print(f"{k}:{','.join(v)}")
                except TimeoutError as e:
                    ...

            for _ in range(len(done)):
                try:
                    item = next(inputs)
                    pending.add(asyncio.create_task(f(item.strip())))  # type: ignore
                except StopIteration:
                    break

    match cmd:
        case "cnames":
            f = partial(cnames, nameserver_f=generate_next_nameserver())

            await run_template(f, iter_stdin(), 300)

        case "cidr":
            for ip_range in iter_stdin():
                for host in unfold_cidr(ip_range):
                    print(str(host))

        case "reverse":
            f = partial(reverse, nameserver_f=generate_next_nameserver())

            await run_template(f, iter_stdin(), 300)

        case "cert":
            f = partial(extract_from_cert)

            await run_template(f, iter_stdin(), 100)

        case "lookup":
            f = partial(lookup, nameserver_f=generate_next_nameserver())

            await run_template(f, iter_stdin(), 300)

        case "query-nameservers":
            addr = argv[2]

            f = partial(lookup, nameserver_f=cycle([addr]).__next__)

            await run_template(f, iter_stdin(), 5)

        case default:
            print("[error] unknown command")
            print_help()
   

if __name__ == "__main__":
    from sys import argv, exit as sys_exit

    try:
        cmd = argv[1]
    except IndexError:
        print_help()

        sys_exit(-1)

    asyncio.run(main(cmd))