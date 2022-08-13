import requests
import json

from typing import Iterator
from recon_helpers import run_from_stdin, threaded
from concurrent.futures import as_completed


def iter_stdin() -> Iterator:
    while True:
        try:
            yield input()
        except EOFError:
            return


@threaded(20)
def probe(tag: str, url: str) -> tuple[str, str, str]:
    return tag, url, str(requests.get(url).status_code)


def parse_robots(robots_txt: str, base_url: str) -> Iterator[tuple[str, str]]:
    for line in filter(
        lambda l:
        l.split(" ")[0] in ["Allow:", "Disallow:"], robots_txt.split("\n")
    ):
        try:
            yield (lambda l: (l[0].strip()[:-1], f"{base_url}{l[1].strip()}"))(
                line.split(" ")
            )
        except IndexError:
            ...


@threaded(5)
def crawl_robots_txt(host: str) -> tuple[str, list[dict[str, str]]]:
    url = f"{host}/robots.txt"
    res = requests.get(url)

    if res.ok:
        lines = parse_robots(
            res.content.decode(),
            host
        )

        @threaded(1)
        def do_not_probe(tag: str, url: str) -> tuple[str, str, str]:
            return tag, url, "-1"

        probes = [
            (lambda c: {"tag": c[0], "url": c[1], "status_code": c[2]})(
                c.result()
            ) for c in as_completed(
                probe(tag, url) if "*" not in url else do_not_probe(tag, url)
                for (tag, url) in lines) if not c.exception()]

        return (
            host, probes
        )

    return (host, [])


if __name__ == "__main__":
    print(json.dumps(run_from_stdin(crawl_robots_txt), indent=4))
