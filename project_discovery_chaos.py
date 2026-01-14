#!/usr/bin/env python3

"""
use project discoveries bug bounty collection (chaos.projectdiscovery.io)
on the command line
"""

from functools import reduce
from io import BytesIO
from zipfile import ZipFile
from argparse import ArgumentParser, Namespace
from dataclasses import dataclass

import re

import requests  # type: ignore[import]

BOUNTY_JSON = "https://chaos-data.projectdiscovery.io/index.json"


@dataclass
class Program:
    name: str
    program_url: str
    swag: bool
    URL: str
    change: int
    count: int
    is_new: bool
    platform: str
    bounty: bool
    last_updated: str

    def __str__(self):
        return f"{self.name}:\n\tlast updated: {self.last_updated}\n\t"\
            f"program url: {self.program_url}\n\t"\
            f"number of domains: {self.count}"


def get_programs() -> list[Program]:
    """fetch and parse program data"""

    def fix_json(j: dict):
        if "swag" not in j.keys():
            j["swag"] = False

        return j

    return [
        Program(**fix_json(p)) for p in requests.get(
            BOUNTY_JSON, timeout=15
        ).json() if p["bounty"] and not p["platform"]
    ]


def get_domains(zip_url: str) -> list[str]:
    """fetch zip from url, extract it, read and concatenate urls"""

    with ZipFile(BytesIO(requests.get(zip_url, timeout=15).content)) as zipfile:
        def open_read_close(name: str) -> list[str]:
            with zipfile.open(name) as file:
                return [line.strip().decode() for line in file.readlines()]

        return reduce(
            lambda doms, n: doms + open_read_close(n), zipfile.namelist(), []
        )


if __name__ == "__main__":
    argument_parser = ArgumentParser("cli for chaos.projectdiscovery.io")

    subparsers = argument_parser.add_subparsers()

    # list programs
    programs_parser = subparsers.add_parser("programs", help="list programs")
    programs_parser.set_defaults(
        func=lambda _: print("\n".join(str(p) for p in get_programs()))
    )

    # list domains for program
    def get_program_domains(args: Namespace):
        """
        find domains for programs matching regex given as an argument (argparse
        callack function)
        """
        regex = re.compile(args.regex)
        matched_programs = [p for p in get_programs() if regex.findall(p.name)]

        zip_urls: list[str] = reduce(
            lambda dom_acc, prog: dom_acc + [prog.URL],
            matched_programs,
            []
        )

        for zip_url in zip_urls:
            print("\n".join(dom for dom in get_domains(zip_url)))

    domains_parser = subparsers.add_parser(
        "domains", help="list domains for given program"
    )
    domains_parser.set_defaults(func=get_program_domains)
    domains_parser.add_argument("regex", type=str)

    parsed_args = argument_parser.parse_args()

    parsed_args.func(parsed_args)
