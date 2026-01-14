#!/usr/bin/env python3

import asyncio
import socket
import ssl
import random

from functools import partial
from ipaddress import AddressValueError, IPv4Address, IPv4Network, IPv6Address, IPv6Network
from itertools import cycle
from random import sample
from sys import stdin,stderr
from typing import Any, Callable, Iterator, Optional
from bisect import bisect_right

from dnslib import DNSRecord  # type: ignore

def iter_stdin() -> Iterator[str]:
    while line := stdin.readline():
        yield line.strip()


# https://en.wikipedia.org/wiki/Linear_congruential_generator
def lazy_global_random_ips(cidr_list: list[str]) -> Iterator[str]:
    networks = []
    cumulative_sizes = []
    total_addresses = 0

    for cidr in cidr_list:
        try:
            net = IPv4Network(cidr.strip()) if ":" not in cidr else IPv6Network(cidr.strip())
            networks.append(net)
            total_addresses += net.num_addresses
            cumulative_sizes.append(total_addresses)
        except Exception:
            continue

    if not networks:
        return

    nbits = (total_addresses - 1).bit_length()
    m_pow2 = 1 << nbits
    
    a = 5
    c = random.getrandbits(nbits) | 1
    state = random.getrandbits(nbits)

    yielded = 0
    while yielded < total_addresses:
        if state < total_addresses:
            net_idx = bisect_right(cumulative_sizes, state)
            
            if net_idx == 0:
                local_offset = state
            else:
                local_offset = state - cumulative_sizes[net_idx - 1]
            
            yield str(networks[net_idx][local_offset])
            yielded += 1
            
        state = (a * state + c) % m_pow2


def generate_next_nameserver() -> Callable[[], str]:
    nameservers = [
        "200.10.231.110",
        "192.133.129.2",
        "45.11.45.11",
        "185.43.135.1",
        "212.72.130.21",
        "156.154.70.10",
        "162.159.36.96",
        "77.88.8.8",
        "76.76.10.5",
        "172.64.36.102",
        "23.95.234.28",
        "151.201.0.39",
        "45.90.28.193",
        "218.146.255.235",
        "199.85.127.20",
        "158.51.134.53",
        "8.20.247.10",
        "208.67.222.222",
        "95.85.95.85",
        "205.171.202.166",
        "51.154.127.161",
        "78.31.67.99",
        "31.3.135.232",
        "141.1.1.1",
        "77.88.8.1",
        "12.127.17.71",
        "52.3.100.184",
        "46.147.193.104",
        "4.2.2.2",
        "66.163.0.161",
        "91.144.22.198",
        "1.1.1.3",
        "64.6.64.6",
        "129.250.35.250",
        "162.159.36.36",
        "50.235.228.46",
        "54.94.175.250",
        "176.121.9.144",
        "151.199.0.39",
        "117.103.228.101",
        "203.251.201.1",
        "209.244.0.4",
        "195.10.195.195",
        "50.204.174.98",
        "76.76.2.2",
        "9.9.9.12",
        "162.159.56.75",
        "165.87.201.244",
        "5.1.66.255",
        "162.159.46.119",
        "94.247.43.254",
        "162.159.36.227",
        "199.85.126.20",
        "64.9.50.67",
        "192.71.166.92",
        "193.202.121.50",
        "210.94.0.7",
        "151.203.0.85",
        "190.93.189.30",
        "212.211.132.4",
        "202.30.143.11",
        "162.159.36.64",
        "151.198.0.38",
        "149.112.122.30",
        "188.225.225.25",
        "168.95.1.1",
        "212.72.130.20",
        "206.253.33.130",
        "2.56.220.2",
        "162.159.46.172",
        "156.154.70.22",
        "195.158.0.3",
        "45.90.28.250",
        "99.99.99.193",
        "164.124.107.9",
        "203.248.252.2",
        "81.3.27.54",
        "212.12.14.49",
        "198.153.192.50",
        "94.140.14.141",
        "76.76.2.5",
        "162.159.56.1",
        "216.170.153.146",
        "162.159.46.177",
        "202.248.37.74",
        "50.234.132.241",
        "162.159.46.51",
        "110.142.40.60",
        "162.159.36.252",
        "217.18.206.22",
        "67.17.215.132",
        "196.3.132.154",
        "216.136.95.2",
        "162.159.46.147",
        "1.0.0.19",
        "193.95.93.243",
        "24.104.140.255",
        "76.76.10.2",
        "151.196.0.38",
        "198.153.194.40",
        "159.69.114.157",
        "151.197.0.39",
        "77.88.8.88",
        "172.64.36.0",
        "162.159.46.18",
        "76.76.10.4",
        "81.16.18.228",
        "203.240.193.11",
        "24.104.140.229",
        "162.159.36.216",
        "217.150.35.129",
        "197.155.92.21",
        "198.153.194.50",
        "1.1.1.1",
        "162.159.50.85",
        "85.9.129.38",
        "4.2.2.5",
        "149.112.112.10",
        "216.21.128.22",
        "156.154.70.7",
        "193.2.246.9",
        "8.20.247.20",
        "1.0.0.2",
        "92.60.50.40",
        "211.115.194.4",
        "141.154.0.68",
        "64.50.242.202",
        "193.227.50.3",
        "211.115.194.5",
        "162.159.36.181",
        "162.159.24.69",
        "162.159.50.27",
        "92.43.224.1",
        "88.208.244.225",
        "193.138.92.130",
        "76.76.2.4",
        "45.90.30.226",
        "1.0.0.3",
        "76.76.2.3",
        "162.159.46.117",
        "195.27.1.1",
        "76.76.10.0",
        "162.159.36.86",
        "193.238.77.62",
        "176.9.93.198",
        "208.67.222.2",
        "12.51.21.245",
        "45.90.30.169",
        "94.140.15.15",
        "12.127.16.67",
        "210.87.250.155",
        "5.11.11.11",
        "41.221.192.167",
        "202.86.149.20",
        "162.159.36.158",
        "162.159.46.197",
        "151.196.0.37",
        "213.211.50.2",
        "176.9.1.117",
        "156.154.71.1",
        "151.201.0.38",
        "193.42.159.2",
        "64.119.80.100",
        "190.93.189.28",
        "45.90.28.189",
        "162.159.36.139",
        "95.143.220.5",
        "162.159.36.46",
        "141.95.6.51",
        "88.198.92.222",
        "62.76.62.76",
        "94.140.14.14",
        "134.75.122.2",
        "45.90.28.126",
        "213.85.168.57",
        "76.76.10.1",
        "198.54.117.11",
        "193.238.77.61",
        "162.159.46.8",
        "45.90.30.129",
        "208.91.112.52",
        "211.115.194.1",
        "9.9.9.9",
        "151.198.0.39",
        "162.159.46.1",
        "209.239.11.98",
        "151.197.0.38",
        "206.253.33.131",
        "194.25.0.60",
        "221.139.13.130",
        "162.159.56.84",
        "194.25.0.52",
        "210.87.253.60",
        "151.202.0.85",
        "204.95.160.2",
        "46.231.32.23",
        "77.88.8.3",
        "75.150.197.154",
        "216.146.36.36",
        "1.1.1.2",
        "195.208.5.1",
        "45.90.28.169",
        "66.28.0.61",
        "162.159.36.185",
        "156.154.70.8",
        "162.159.46.90",
        "162.159.46.166",
        "149.112.112.11",
        "193.226.61.1",
        "194.108.42.2",
        "162.159.46.28",
        "162.159.36.199",
        "35.155.221.215",
        "156.154.70.1",
        "207.68.32.39",
        "50.237.34.1",
        "84.54.64.35",
        "45.90.30.193",
        "212.12.14.122",
        "92.222.117.114",
        "156.154.71.2",
        "216.165.129.157",
        "151.197.0.37",
        "199.85.127.10",
        "96.69.146.137",
        "162.159.36.224",
        "162.159.50.42",
        "212.113.0.3",
        "185.74.5.1",
        "162.159.46.214",
        "95.158.129.2",
        "35.167.25.37",
        "151.203.0.84",
        "62.82.138.5",
        "172.64.36.103",
        "149.112.122.10",
        "193.58.251.251",
        "156.154.70.16",
        "12.127.17.72",
        "208.72.160.67",
        "209.130.136.2",
        "210.94.0.73",
        "45.90.30.126",
        "195.140.195.21",
        "156.154.71.25",
        "9.9.9.11",
        "195.46.39.40",
        "76.76.2.1",
        "149.112.122.20",
        "194.150.168.169",
        "185.74.5.5",
        "64.132.94.250",
        "64.6.65.6",
        "177.184.176.5",
        "165.87.13.129",
        "151.202.0.84",
        "198.153.192.40",
        "66.163.0.173",
        "76.76.2.0",
        "107.0.218.126",
        "5.11.11.5",
        "216.229.0.25",
        "8.8.8.8",
        "208.67.220.220",
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
        
        if 'subjectAltName' in cert:
            names.update(str(x[1]) for x in cert['subjectAltName'])
            
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
    async def run_template(f, inputs, parallel):
        queue = asyncio.Queue(maxsize=parallel)

        async def worker():
            while True:
                item = await queue.get()
                try:
                    k, v = await f(item)
                    if k:
                        print(f"{k}:{','.join(v)}")
                except Exception:
                    pass
                finally:
                    queue.task_done()

        workers = [asyncio.create_task(worker()) for _ in range(parallel)]

        for item in inputs:
            await queue.put(item.strip())

        await queue.join()

        for w in workers:
            w.cancel()

    match cmd:
        case "cnames":
            f = partial(cnames, nameserver_f=generate_next_nameserver())

            await run_template(f, iter_stdin(), 1000)

        case "cidr":
            cidr_inputs = [line.strip() for line in stdin if line.strip()]
            for ip in lazy_global_random_ips(cidr_inputs):
                print(ip)

        case "reverse":
            f = partial(reverse, nameserver_f=generate_next_nameserver())

            await run_template(f, iter_stdin(), 1000)

        case "cert":
            f = partial(extract_from_cert)

            await run_template(f, iter_stdin(), 1000)

        case "lookup":
            f = partial(lookup, nameserver_f=generate_next_nameserver())

            await run_template(f, iter_stdin(), 1000)

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