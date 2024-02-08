"""
Takes xml files from nmap scans and genereates an xml for cherrytree
https://www.giuspen.com/cherrytree/

author: tav
"""

import sys
import time
from typing import Iterator
from xml.etree import ElementTree
import itertools


def set_default_keys(xml_node: ElementTree.Element) -> None:
    """Set node keys to default."""

    xml_node.set("foreground", "")
    xml_node.set("is_bold", "False")
    xml_node.set("prog_lang", "custom_colors")
    xml_node.set("readonly", "False")
    xml_node.set("ts_creation", "{:.2f}".format(time.time()))
    xml_node.set("ts_lastsave", "{:.2f}".format(time.time()))


def new_host_node(
    xml_root: ElementTree.Element,
    addr: str,
    hostnames: list[str],
    node_id: int
) -> ElementTree.Element:
    """
    Add a host node

    Args:
        xml_root (ElementTree.Element): the cherrytree root node
        nmap_host (libnmap.objects.host.NmapHost): the host represented by this
                                                   node
        node_id (int): id of the new node, must be unique
    """

    xml_host = ElementTree.SubElement(xml_root, "node")

    xml_host_name = addr
    if hostnames:
        xml_host_name += " (" + ", ".join(hostnames) + ")"

    xml_host.set("custom_icon_id", "165")
    xml_host.set("name", xml_host_name)
    xml_host.set("tags", "")
    xml_host.set("unique_id", str(node_id))

    set_default_keys(xml_host)

    return xml_host


def get_port_icon(pnum: int, proto: str) -> int:
    """
    Set information on port node.

    Args:
        port_node (xml.etree.ElementTree.Element): node to set properties on
        pnum (int): port number
        transpp (str): name of transport layer protocol (normally tcp or udp)
    """

    match pnum:
        case 80 | 8080 | 8000 | 8888 | 443 | 8443:
            return 17
        case 21:
            return 44
        case 20:
            if proto == "udp":
                return 44
        case 22 | 23: return 17
        case 135 | 136 | 137 | 138 | 139 | 445:
            return 42
        case 161:
            if proto == "udp":
                return 42
        case 53:
            return 39
        case 25 | 110 | 143 | 465 | 587 | 993 | 995:
            if proto == "tcp":
                return 16

    return 38


def new_port_node(
    xml_host: ElementTree.Element,
    node_id: int,
    proto: str,
    portid: int,
    service: str,
    script_result: str,
    state: str
) -> ElementTree.Element:
    """
    Add a new port subnode to a host node.

    Args:
        xml_host (xml.etree.ElementTree.Element): host node the port node
                                                  should associated with
        nmap_host (libnmap.objects.host.NmapHost): host from nmap scan result
    """

    xml_port = ElementTree.SubElement(xml_host, "node")
    xml_port.set("name", f"{portid} ({proto})")

    set_default_keys(xml_port)

    if service:
        rich_text = ElementTree.SubElement(xml_port, "rich_text")
        rich_text.text = "{} ({}): {}\n\n{}"\
                         .format(proto,
                                 state,
                                 service,
                                 script_result)
        xml_port.set("tags", service)

    xml_port.set("custom_icon_id", str(get_port_icon(portid, service)))

    xml_port.set("unique_id", str(node_id))

    return xml_port


def parse_nmap_xml(xml: ElementTree.Element)\
        -> Iterator[
            tuple[str, list[str], list[tuple[str, int, str, str, str]]]
]:
    hosts = [
        h for h in xml if h.tag == "host"
    ]

    for host in hosts:
        opt_address = [a for a in host if a.tag == "address"].pop().get("addr")
        address = opt_address if opt_address else ""

        hostsnames_root = [a for a in host if a.tag == "hostnames"]

        if hostsnames_root:
            hostnames = [n for n in [h.get("name")
                                     for h in hostsnames_root.pop()] if n]
        else:
            hostnames = []

        ports_root = [a for a in host if a.tag == "ports"].pop()
        ports = [
            (proto, int(portid), output, service, state)
            for
            (proto, portid, output, service, state) in [
                (
                    p.get("protocol"),
                    p.get("portid"),
                    [n for n in (s.get("name")
                                 for s in p if s.tag == "service") if n].pop(),
                    "\n".join(
                        s for s in (
                            s.get("output") for s in p if s.tag == "script"
                        ) if s
                    ),
                    [n for n in (s.get("state")
                                 for s in p if s.tag == "state") if n].pop()
                ) for p in ports_root if p.tag == "port"
            ] if proto and portid]

        yield (address, hostnames, ports)


def convert_file(files: list[str]) -> ElementTree.Element:
    """
    Convert nmap scans in xml formt into cherrytree xmls.

    Args:
        files (list[str]): list of filesystem paths of nmap scan xmls
    """

    id_counter = itertools.count(start=1, step=1)
    xml_root = ElementTree.Element("cherrytree")

    def get_reports() -> Iterator[
        Iterator[
            tuple[str, list[str], list[tuple[str, int, str, str, str]]]
        ]
    ]:
        for filename in files:
            print("[*] parsing file {}".format(filename), file=sys.stderr)
            with open(filename, "r") as f:
                yield parse_nmap_xml(ElementTree.XML(f.read()))

    results = sorted(list(h for r in get_reports()
                     for h in r), key=lambda x: x[0][0])

    for host_result in results:
        addr, hostnames, ports = host_result
        host = new_host_node(xml_root, addr, hostnames, next(id_counter))

        for port in ports:
            new_port_node(host, next(id_counter), *port)

    return xml_root


def main() -> None:
    """
    Main method that should be called for standalone usage (I do not know which
    other usage there might be)
    """

    if not sys.argv[1:]:
        print("Usage: {} [scan1.xml] [scan2.xml] ... [scanN.xml]"
              .format(sys.argv[0]), file=sys.stderr)
        return

    cherrytree_xml = convert_file(sys.argv[1:])

    print(ElementTree.tostring(cherrytree_xml).decode())


if __name__ == "__main__":
    main()
