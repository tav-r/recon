from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from typing import Callable, Any, Iterable

import fileinput
import functools


def threaded(nthreads: int) -> Callable[
    [Callable[..., Any]], Callable[..., Any]
]:
    def _g(f: Callable[..., Any]) -> Callable[..., Any]:
        pool = ThreadPoolExecutor(nthreads)

        @functools.wraps(f)
        def _f(*args: list[Any], **kwargs: dict[str, Any]) -> Any:
            return pool.submit(f, *args, **kwargs)

        return _f
    return _g


def run_from_iter(
    f: Callable[[str], Future[tuple[str, Any]]],
    iter_: Iterable,
    result_filter: Callable[[tuple[str, Any]], bool] = lambda x: True
) -> dict[str, list[Any]]:
    return dict(
        filter(
            result_filter,
            (c.result() for c in as_completed(
                f(name) for name in iter_
            ))
        )
    )


def run_from_stdin(
    f: Callable[[str], Future[tuple[str, Any]]]
) -> dict[str, list[Any]]:
    try:
        with fileinput.input() as file_input:
            res = run_from_iter(
                f,
                [n.strip() for n in file_input if n.strip()],
                lambda x: x[1]
            )

    except KeyboardInterrupt:
        print("Interrupted, exiting...")

    return res
