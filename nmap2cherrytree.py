"""
Takes xml files from nmap scans and genereates an xml for cherrytree
https://www.giuspen.com/cherrytree/

author: tav
"""

import sys
import time
import xml
import itertools
import pprint
from libnmap.parser import NmapParser


def is_http(pnum, transpp):
    """Helper method to check if portnumber/transportprotocol may be http"""
    return pnum in [80, 443, 8000, 8080, 8888] and transpp == "tcp"


def set_default_keys(xml_node):
    """Set node keys to default."""
    xml_node.set("foreground", "")
    xml_node.set("is_bold", "False")
    xml_node.set("prog_lang", "custom_colors")
    xml_node.set("readonly", "False")
    xml_node.set("ts_creation", "{:.2f}".format(time.time()))
    xml_node.set("ts_lastsave", "{:.2f}".format(time.time()))


def new_host_node(xml_root, nmap_host, node_id):
    """
    Add a host node

    Args:
        xml_root (xml.etree.ElementTree.Element): the cherrytree root node
        nmap_host (libnmap.objects.host.NmapHost): the host represented by this
                                                   node
        node_id (int): id of the new node, must be unique
    """
    xml_host = xml.etree.ElementTree.SubElement(xml_root, "node")

    xml_host_name = nmap_host.address
    if nmap_host.hostnames:
        xml_host_name += " (" + ", ".join(nmap_host.hostnames) + ")"

    rich_text = xml.etree.ElementTree.SubElement(xml_host, "rich_text")
    rich_text.text = pprint.pformat(nmap_host.scripts_results)

    xml_host.set("custom_icon_id", "21")
    xml_host.set("name", xml_host_name)
    xml_host.set("tags", "")
    xml_host.set("unique_id", str(node_id))

    set_default_keys(xml_host)

    return xml_host


def set_port_info(port_node, pnum, transpp):
    """
    Set information on port node.

    Args:
        port_node (xml.etree.ElementTree.Element): node to set properties on
        pnum (int): port number
        transpp (str): name of transport layer protocol (normally tcp or udp)
    """
    if is_http(pnum, transpp):
        port_node.set("custom_icon_id", "17")
    elif pnum in [22] or (pnum in [23] and transpp == "tcp"):
        port_node.set("custom_icon_id", "22")
    elif pnum in [21] or (pnum in [20] and
                          transpp == "udp"):
        port_node.set("custom_icon_id", "44")
    elif pnum in [135, 136, 137, 138, 139, 445] or\
            pnum in [161] and transpp == "udp":
        port_node.set("custom_icon_id", "42")
    elif pnum in [53]:
        port_node.set("custom_icon_id", "39")
    elif pnum in [25, 110, 143, 465, 587, 993, 995] and\
            transpp == "tcp":
        port_node.set("custom_icon_id", "16")
    else:
        port_node.set("custom_icon_id", "38")


def new_port_node(xml_host, nmap_host, port_tuple, node_id):
    """
    Add a new port subnode to a host node.

    Args:
        xml_host (xml.etree.ElementTree.Element): host node the port node
                                                  should associated with
        nmap_host (libnmap.objects.host.NmapHost): host from nmap scan result
    """
    portnumber, transport_protocol = port_tuple[0], port_tuple[1]

    xml_port = xml.etree.ElementTree.SubElement(xml_host, "node")
    xml_port.set("name", str(portnumber))

    service = nmap_host.get_service(portnumber)

    set_default_keys(xml_port)

    if service:
        rich_text = xml.etree.ElementTree.SubElement(xml_port, "rich_text")
        rich_text.text = "{} ({}): {} - {}"\
                         .format(service.protocol,
                                 "open" if service.open() else "not open",
                                 service.protocol,
                                 service.banner)
        xml_port.set("tags", service.protocol)

    set_port_info(xml_port, portnumber, transport_protocol)

    if is_http(portnumber, transport_protocol):
        prefix = "https://" if portnumber == 443 else "http://"
        rich_text.text += "\n" + prefix + nmap_host.address + ":" +\
                          str(portnumber) + "/"

    xml_port.set("unique_id", str(node_id))

    return xml_port


def convert_file(files):
    """
    Convert nmap scans in xml formt into cherrytree xmls.

    Args:
        files (list[str]): list of filesystem paths of nmap scan xmls
    """
    id_counter = itertools.count(start=1, step=1)
    xml_root = xml.etree.ElementTree.Element("cherrytree")

    def get_reports():
        for filename in files:
            print("[*] parsing file {}".format(filename), file=sys.stderr)
            yield NmapParser.parse_fromfile(filename)

    hosts = []
    for scanned_host in ([report.hosts for report in get_reports()]):
        hosts += scanned_host

    sorted_hosts = sorted(hosts, key=lambda x: [int(e)
                                                for e in x.address.split(".")])

    for host_result in sorted_hosts:
        host = new_host_node(xml_root, host_result, next(id_counter))

        for port in host_result.get_ports():
            new_port_node(host, host_result, port, next(id_counter))

    return xml_root


def main():
    """
    Main method that should be called for standalone usage (I do not know which
    other usage there might be)
    """
    if not sys.argv[1:]:
        print("Usage: {} [scan1.xml] [scan2.xml] ... [scanN.xml]"
              .format(sys.argv[0]), file=sys.stderr)
        return

    cherrytree_xml = convert_file(sys.argv[1:])

    print(xml.etree.ElementTree.tostring(cherrytree_xml).decode())


if __name__ == "__main__":
    main()
