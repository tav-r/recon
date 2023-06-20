from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from typing import Callable, Any, Iterable, Iterator
from sys import stdin
from time import sleep

import functools


def threaded(nthreads: int) -> Callable[
    [Callable[..., Any]], Callable[..., Any]
]:
    def _g(f: Callable[..., Any]) -> Callable[..., Any]:
        pool = ThreadPoolExecutor(max_workers=nthreads)

        @functools.wraps(f)
        def _f(*args: list[Any], **kwargs: dict[str, Any]) -> Any:
            return pool.submit(f, *args, **kwargs)

        return _f
    return _g

def run_from_iter(
    f: Callable[[str], Future[tuple[str, Any]]],
    iter_: Iterable,
    result_filter: Callable[[tuple[str, Any]], bool] = lambda _: True
) -> Iterator[tuple[str, Any]]:
    futures: list[Future[Any]] = []

    while True:
        while len(futures) < 500:
            try:
                futures.append(f(next(iter_)))  # type: ignore
            except StopIteration:
                for c in as_completed(futures):
                    res = c.result()
                    if result_filter(res):
                        yield res
                return

        for c in futures:
            if c.done():
                futures.remove(c)
                res = c.result()
                if result_filter(res):
                    yield res
            

def iter_stdin() -> Iterator[str]:
    while line := stdin.readline():
        yield line.strip()

def run_from_stdin(
    f: Callable[[str], Future[tuple[str, Any]]]
) -> Iterator[tuple[str, Any]]:
    try:
        for res in run_from_iter(
            f,
            iter_stdin(),
            lambda res: res[1]
        ):
            yield res

    except KeyboardInterrupt:
        print("Interrupted, exiting...")
