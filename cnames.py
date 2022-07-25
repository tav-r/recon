import functools
import json
import fileinput

import dns
import dns.resolver

from typing import Any, Optional, Callable, Iterator, Iterable, TypeVar, List,\
    Dict
from concurrent.futures import Future, ThreadPoolExecutor, as_completed


# some interesting domains, maybe add some more later on
RT = TypeVar("RT")
TAKEOVER_DOMAINS = [
    ".agilecrm.com",
    ".cdn.airee.ru",
    ".amazonaws.com",
    ".cloudapp.net",
    ".cloudapp.azure.com",
    ".azurewebsites.net",
    ".blob.core.windows.net",
    ".cloudapp.azure.com",
    ".azure-api.net",
    ".azurehdinsight.net",
    ".azureedge.net",
    ".azurecontainer.io",
    ".database.windows.net",
    ".azuredatalakestore.net",
    ".search.windows.net",
    ".azurecr.io",
    ".redis.cache.windows.net",
    ".azurehdinsight.net",
    ".servicebus.windows.net",
    ".visualstudio.com",
    ".youtrack.cloud",
    ".ngrok.io",
    ".strikinglydns.com",
    ".wordpress.com",
    ".intercom.help",
    ".uptimerobot.com",
    ".github.io",
    ".helpscoutdocs.com"
]


def is_takeover_domain(domain: str) -> bool:
    return any(
        domain.endswith(tkvr) or domain.endswith(f"{tkvr}.")
        for tkvr in TAKEOVER_DOMAINS
    )


def threaded(f: Callable[..., Any]) -> Callable[..., Any]:
    pool = ThreadPoolExecutor(20)

    @functools.wraps(f)
    def _f(*args: List[Any], **kwargs: Dict[Any, Any]) -> Future[RT]:
        return pool.submit(f, *args, **kwargs)

    return _f


def chunked_iterator(i: Iterable, chunk_size: int) -> Iterator:
    buffer = []
    for n, v in enumerate(i, 1):
        buffer.append(v)
        if not n % chunk_size:
            yield buffer
            buffer = []

    # yield buffer if we are done iterating and buffer is not yet empty
    if buffer:
        yield buffer


@threaded
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
    filter_: Optional[Callable[[str], bool]] = None
) -> dict[str, list[str]]:
    return dict(
        c.result() for c in as_completed(
            resolve(name, "CNAME") for name in iter_
        ) if not filter_ or filter_(c.result())
    )


def run_from_stdin() -> dict[str, list[str]]:
    try:
        with fileinput.input() as file_input:
            res = run_from_iter(
                [n.strip() for n in file_input if n.strip()],
                filter_=lambda x: any(
                    is_takeover_domain(domain) for domain in x[1]
                )
            )

    except KeyboardInterrupt:
        print("Interrupted, exiting...")

    return res


if __name__ == "__main__":
    print(json.dumps(run_from_stdin(), indent=4))
