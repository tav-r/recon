import aiohttp
import asyncio

from typing import Iterator
from concurrent.futures import as_completed
from sys import stdin


async def probe(client: aiohttp.ClientSession, tag: str, url: str) -> int:
    return (await client.get(url)).status


def parse_robots(robots_txt: str, base_url: str) -> Iterator[tuple[str, str]]:
    for (directive, path) in (
        l.split(" ", 1) for l in robots_txt.split("\n")
        if any(l.startswith(prefix) for prefix in ["Allow:", "Disallow:"])
    ):
        try:
            yield (directive, f"{base_url}{path}")
        except IndexError:
            ...


async def crawl_robots_txt(client: aiohttp.ClientSession, host: str) -> None:
    host = host[:-1] if host.endswith("/") else host

    robots_url = f"{host}/robots.txt"
    robots_url = robots_url if robots_url[:6] in ["http:/", "https:"] else "https://" + robots_url

    res = await client.get(robots_url)

    if res.ok:
        semaphore = asyncio.Semaphore(4)

        lines = parse_robots(
            (await res.content.read()).decode(),
            host
        )

        async def worker(tag: str, url: str):
            async with semaphore:
                code = await probe(client, tag, url)
                print(f"[+] {tag} {url} {code}")

        jobs = [worker(tag, url) for (tag, url) in set(lines) if "*" not in url]

        await asyncio.gather(*jobs)

    await client.close()


async def main():
    client = aiohttp.ClientSession()

    async for res in (await crawl_robots_txt(client, l.strip()) for l in stdin):
        ...

if __name__ == "__main__":
    asyncio.run(main())