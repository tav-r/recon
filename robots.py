import requests
import json

from typing import Iterator, cast
from recon_helpers import run_from_stdin, threaded
from concurrent.futures import as_completed


def iter_stdin() -> Iterator:
    while True:
        try:
            yield input()
        except EOFError:
            return


@threaded(20)
def probe(url: str) -> int:
    return requests.get(url).status_code


def parse_robots(robots_txt: str, base_url: str) -> Iterator[tuple[str, str]]:
    for line in filter(
        lambda l:
        l.split(" ")[0] in ["Allow:", "Disallow:"], robots_txt.split("\n")
    ):
        try:
            yield (lambda l: (l[0].strip(), f"{base_url}{l[1].strip()}"))(
                line.split(" ")
            )
        except IndexError:
            ...


@threaded(5)
def crawl_robots_txt(host: str) -> tuple[str, list[dict[str, str]]]:
    url = f"{host}/robots.txt"
    res = requests.get(url)

    if res.ok:
        tags, lines = zip(*parse_robots(
            res.content.decode(),
            host
        ))

        probes = [cast(int, c.result()) for c in as_completed(
            probe(line) for line in lines) if not c.exception()]

        return (
            (host, [
                {"tag": tag, "line": line, "status_code": str(probe)}
                for (tag, line, probe) in zip(tags, lines, probes)
            ])
        )

    return (host, [])


if __name__ == "__main__":
    print(json.dumps(run_from_stdin(crawl_robots_txt), indent=4))
