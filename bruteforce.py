from concurrent.futures import Future
from typing import Callable, cast
import requests
from requests import Response
from recon_helpers import threaded, run_from_stdin, run_from_iter
from sys import argv
from random import randint
from itertools import count
import json


def randstr(n: int) -> str:
    return "".join(c for (c, _) in zip(
        filter(
            lambda c: c.isalnum(),
            (chr(randint(21, 127)) for _ in count())
        ),
        range(n)
    ))


@threaded(20)
def get(url: str) -> tuple[str, Response]:
    res = requests.get(url, allow_redirects=True)
    return url, res


def bruteforce(url: str) -> Callable[
    [str], Future[tuple[str, tuple[int, int]]]
]:
    def _f(path: str) -> Future[tuple[str, tuple[int, int]]]:
        return get(url + ("/" if not url.endswith("/") else "") + path)

    return _f


def filter_by_avg_len(success: list[tuple[str, Response]]) -> list[str]:
    avg_len = sum(len(r.content) for (_, r) in success) / len(success)
    return [p for (p, res) in success
            if len(res.content) > avg_len * 1.1
            or len(res.content) < avg_len * 0.9
            ]


def filter_by_status_code(success: list[tuple[str, Response]]) -> list[str]:
    return [
        p for (p, s) in success if s.status_code == 200
    ]


def evaluate(paths: list[str]) -> Callable[
    [str], Future[tuple[str, list[str]]]
]:
    @threaded(10)
    def _g(url: str) -> tuple[str, list[str]]:
        res = requests.get(
            url + ("/" if not url.endswith("/") else "") + randstr(20)
        )

        if res.status_code == 200:
            res_filter = filter_by_avg_len
        else:
            res_filter = filter_by_status_code

        success = [
            (p, cast(Response, res)) for (p, res) in run_from_iter(
                bruteforce(url), paths
            ).items() if cast(Response, res).status_code == 200
        ]

        return url, res_filter(success)

    return _g


def main() -> None:
    with open(argv[1], "r") as wordlist:
        paths = [line.strip() for line in wordlist]

    del(argv[1])

    print(json.dumps(run_from_stdin(evaluate(paths)), indent=4))


if __name__ == "__main__":
    main()
