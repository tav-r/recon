import functools
import json
import fileinput

import dns
import dns.resolver

from typing import Any, Optional, Callable, Iterable, TypeVar, List, Dict
from concurrent.futures import Future, ThreadPoolExecutor, as_completed


RT = TypeVar("RT")


def threaded(nthreads: int) -> Callable[
    [Callable[..., Any]], Callable[..., Any]
]:
    def _g(f: Callable[..., Any]) -> Callable[..., Any]:
        pool = ThreadPoolExecutor(nthreads)

        @functools.wraps(f)
        def _f(*args: List[Any], **kwargs: Dict[Any, Any]) -> Future[RT]:
            return pool.submit(f, *args, **kwargs)

        return _f
    return _g


@threaded(20)
def resolve(domain: str, type_: str) -> tuple[Optional[str], list[str]]:
    def _f(domain: str) -> list[str]:
        try:
            res = [
                d.to_text().split(" ")[-1] for a in
                dns.resolver.resolve(domain, type_, lifetime=2)
                .response.answer for d in a
            ]

            return res + [c for d in res for c in _f(d) if c not in res]

        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.exception.Timeout,
            dns.resolver.NoNameservers,
            dns.name.EmptyLabel
        ):
            return []

    return domain, _f(domain)


def run_from_iter(
    iter_: Iterable,
) -> dict[str, list[str]]:
    return dict(
        filter(
            lambda x: x[1],
            (c.result() for c in as_completed(
                resolve(name, "CNAME") for name in iter_
            ))
        )
    )


def run_from_stdin() -> dict[str, list[str]]:
    try:
        with fileinput.input() as file_input:
            res = run_from_iter(
                [n.strip() for n in file_input if n.strip()]
            )

    except KeyboardInterrupt:
        print("Interrupted, exiting...")

    return res


if __name__ == "__main__":
    print(json.dumps(run_from_stdin(), indent=4))
