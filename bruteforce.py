from concurrent.futures import Future
from typing import Callable, Optional, cast
import requests
from requests import Response
from recon_helpers import threaded, run_from_stdin, run_from_iter
from sys import argv
from random import randint
from itertools import count
import json


requests.packages.urllib3.disable_warnings()


def randstr(n: int) -> str:
    return "".join(c for (c, _) in zip(
        filter(
            lambda c: c.isalnum(),
            (chr(randint(21, 127)) for _ in count())
        ),
        range(n)
    ))


@threaded(20)
def get(url: str) -> tuple[str, Optional[Response]]:
    try:
        res = requests.get(url, allow_redirects=True, timeout=2, verify=False)
    except requests.exceptions.RequestException:
        return url, None

    return url, res


def bruteforce(url: str) -> Callable[
    [str], Future[tuple[str, Optional[Response]]]
]:
    def _f(path: str) -> Future[tuple[str, Optional[Response]]]:
        return get(url + ("/" if not url.endswith("/") else "") +
                   (path[1:] if path.startswith("/") else path))

    return _f


def filter_len_outliers(
    baseline: int,
    success: list[tuple[str, Response]]
) -> list[tuple[str, int, int]]:
    assert success
    assert all(success)

    baseline_weight = 1

    mean = (sum(len(r.content) for (_, r) in success) +
            len(success) * baseline_weight * baseline) /\
        (len(success) * (baseline_weight + 1))

    variance = (sum((mean - len(r.content))**2 for (_, r)
                    in success) + (mean - baseline)**2 * baseline_weight) /\
        (len(success) * (baseline_weight + 1))

    standard_deviation: float = variance ** (1/2)

    if not standard_deviation:
        return []

    def standard_score(cl: int) -> float:
        return (cl - mean) / standard_deviation

    return [
        (p, res.status_code, len(res.content)) for (p, res) in success
        if res and (abs(standard_score(len(res.content))) > 0.5)
    ]


def evaluate(paths: list[str]) -> Callable[
    [str], Future[tuple[str, list[str]]]
]:
    @ threaded(10)
    def _g(url: str) -> tuple[str, list[tuple[str, int, int]]]:
        try:
            baseline_res = requests.get(
                url + ("/" if not url.endswith("/") else "") +
                randstr(30) + ".html",
                allow_redirects=True,
                timeout=2,
                verify=False
            )
        except requests.exceptions.RequestException:
            return url, []

        success = [
            (p, cast(Response, res)) for (p, res) in run_from_iter(
                bruteforce(url), paths, lambda x: x[1] is not None
            ).items()
        ]

        if success:
            return url, filter_len_outliers(len(baseline_res.content), success)

        return url, []

    return _g


def main() -> None:
    with open(argv[1], "r") as wordlist:
        paths = [line.strip() for line in wordlist]

    del(argv[1])

    print(json.dumps(run_from_stdin(evaluate(paths)), indent=4))


if __name__ == "__main__":
    main()
