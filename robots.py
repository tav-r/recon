import requests
import json
import argparse

from typing import Iterator, Optional


def iter_stdin() -> Iterator:
    while True:
        try:
            yield input()
        except EOFError:
            return
    

def probe(url: str):
    return requests.get(url).status_code


def parse_robots(robots_txt: str, base_url: str):
    for line in filter(
        lambda l:
        l.split(" ")[0] in ["Allow:", "Disallow:"], robots_txt.split("\n")
    ):
        yield (lambda l: (l[0].strip(), f"{base_url}{l[1].strip()}"))(
            line.split(" ")
        )


def crawl_robots_txt(domain: str, port: Optional[int] = None, no_https=False):
    port = "" if not port else f":{port}"
    scheme = "https" if not no_https else "http"
    base_url = f"{scheme}://{domain}{port}"
    url = f"{base_url}/robots.txt"
    res = requests.get(url)

    if res.ok:
        return {
            url: [
                (cat, line, probe(line))
                for cat, line in parse_robots(
                    res.content.decode(),
                    base_url
                )
            ]
        }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "-p", "--port", dest="port", help="http port to use", type=int,
        default=None
    )
    ap.add_argument(
        "-n", "--no-https", dest="no_https", help="use unencrypted HTTP",
        default=False, action="store_true"
    )

    args = ap.parse_args()

    print(json.dumps({
        domain: crawl_robots_txt(
            domain, args.port, args.no_https
        ) for domain in iter_stdin()
    }, indent=4))


if __name__ == "__main__":
    main()