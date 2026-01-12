import asyncio
import aiohttp
from os import environ
from typing import List

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

async def fetch_text(session: aiohttp.ClientSession, url: str, **kwargs) -> str:
    async with session.get(url, **kwargs) as response:
        response.raise_for_status()
        return await response.text()

async def post_fetch_json(session: aiohttp.ClientSession, url: str, **kwargs) -> dict:
    async with session.post(url, **kwargs) as response:
        response.raise_for_status()
        return await response.json()

async def get_fetch_json(session: aiohttp.ClientSession, url: str, **kwargs) -> dict:
    async with session.get(url, **kwargs) as response:
        response.raise_for_status()
        return await response.json()


async def thc_db(session: aiohttp.ClientSession, domain: str) -> List[str]:
    THC_URL = "https://ip.thc.org/api/v1/subdomains/download"

    text = await fetch_text(session, f"{THC_URL}?domain={domain}")
    return [l.strip() for l in text.splitlines() if l.strip()][1:]

async def kaeferjaeger_snis(session: aiohttp.ClientSession, domain: str) -> List[str]:
    PROVIDERS = ["amazon", "digitalocean", "google", "microsoft"]
    
    async def fetch_provider(provider: str, domain: str):
        url = f"https://kaeferjaeger.gay/sni-ip-ranges/{provider}/ipv4_merged_sni.txt"

        results = []
        async with session.get(url) as resp:
            if resp.status != 200: return []
            async for line in resp.content:
                line_decoded = line.decode('utf-8', errors='ignore')

                if not " -- " in line_decoded:
                    continue

                for domain in [dom for dom in line_decoded.split(" -- ")[1].strip().strip("[]").split(" ") if dom.endswith(domain)]:
                     results.append(domain)

        return results

    tasks = [fetch_provider(p, domain) for p in PROVIDERS]
    provider_results = await asyncio.gather(*tasks)
    
    return [item for sublist in provider_results for item in sublist]

async def hackertarget_db(session: aiohttp.ClientSession, domain: str) -> List[str]:
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    
    if (ht_api_key := environ.get("HT_API_KEY")):
        url += f"&apikey={ht_api_key}"

    text = await fetch_text(session, url)

    return [l.split(',')[0] for l in text.splitlines() if l.strip()]

async def certkit_log(session: aiohttp.ClientSession, domain: str) -> List[str]:
    URL = "https://ct.certkit.io/search"

    data = await post_fetch_json(session, URL, json={"domain": domain, "sort": ""})
    results = []
    for res in data.get("results", []):
        dns_names = res.get("dnsNames", [])
        common_name = res.get("commonName")
        
        candidates = dns_names if dns_names else []
        if common_name:
            candidates.append(common_name)
            
        for entry in set(candidates):
            results.append(entry)
    return results

async def crt_sh(session: aiohttp.ClientSession, domain: str) -> List[str]:
    url = f"https://crt.sh/json?identity={domain}&exclude=expired"

    data = await get_fetch_json(session, url)

    cns = [d["common_name"] for d in data if d["common_name"]]
    ids = [n for d in data for n in d["name_value"].split("\n")]

    return cns + ids

async def main(domain: str):
    timeout = aiohttp.ClientTimeout(total=60)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        tasks = [
            thc_db(session, domain),
            kaeferjaeger_snis(session, domain),
            hackertarget_db(session, domain),
            certkit_log(session, domain),
            crt_sh(session, domain)
        ]

        for future in asyncio.as_completed(tasks):
            results = await future
            for res in results:
                print(res)

if __name__ == "__main__":
    from sys import argv

    if len(argv) < 2:
        print(f"Usage: python {argv[0]} <domain>")
        exit(1)
        
    domain = argv[1]

    asyncio.run(main(domain))
