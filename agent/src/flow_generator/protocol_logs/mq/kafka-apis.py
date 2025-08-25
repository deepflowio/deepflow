#!/usr/bin/python3

from bisect import bisect_left
from lxml import html
import requests
import sys

# The first page contains header version for different api key versions.
# However, it does not contain very old api keys.
# The second page does have all versions for all api keys, but it does not contain header version.
HEADER_VERSION_URL = "https://kafka.apache.org/protocol.html"
API_KEY_URL = "https://kafka.apache.org/39/protocol.html"

def fetch_header_versions(key, type):
    header_versions = []
    prefix = f"{key} {type}"
    for div in html.fromstring(requests.get(HEADER_VERSION_URL).text).xpath("//div"):
        api = next(div.iter("pre"), None)
        if api is None or api.text is None or not api.text.startswith(prefix):
            continue
        api_version = api.text.split("Version: ")[1].split(")")[0]

        version = next(div.iter("p"), None)
        if version is None:
            continue
        version = next(version.iter("b"), None)
        if version is None:
            continue
        version = version.tail
        if version is None:
            continue

        header_versions.append((int(api_version), version.strip()))

    return header_versions

def fetch_apis(key, type):
    apis = []
    prefix = f"{key} {type}"
    for api in html.fromstring(requests.get(API_KEY_URL).text).xpath("//pre"):
        if api.text is None or not api.text.startswith(prefix):
            continue
        lines = api.text.split("\n")
        name, info = lines[0].split(" => ", 1)
        version = name.split("Version: ")[1].split(")")[0]
        lines[0] = info
        for i in range(len(lines)):
            lines[i] = lines[i].rstrip()
        apis.append((int(version), "\n".join(lines)))
    return apis

def merge_apis(apis):
    merged = []
    offset = 0
    while offset < len(apis):
        base = apis[offset]
        versions = [base[0]]
        if offset + 1 == len(apis):
            merged.append((versions, base[1]))
            break
        for index, api in enumerate(apis[offset + 1:]):
            if api[1] == base[1]:
                versions.append(api[0])
                continue
            else:
                merged.append((versions, base[1]))
                offset = index + offset + 1
                break
        else:
            merged.append((versions, base[1]))
            return merged
    return merged

def main():
    if len(sys.argv) != 3:
        print("Usage: kafka-apis.py <api_key> <type>")
        sys.exit(1)

    api_key = sys.argv[1]
    api_type = sys.argv[2].lower()

    if api_type not in ["request", "response"]:
        print("Type must be 'Request' or 'Response'")
        sys.exit(1)

    api_type = api_type.capitalize()

    header_versions = fetch_header_versions(api_key, api_type)
    result = fetch_apis(api_key, api_type)
    if result:
        for versions, info in merge_apis(result):
            hvs = []
            for v in versions:
                loc = bisect_left(header_versions, (v, ""))
                if loc == len(header_versions):
                    hvs.append(header_versions[-1][1])
                else:
                    hvs.append(header_versions[loc][1])
            assert len(set(hvs)) == 1

            title = f"{api_key} {api_type} {versions} header version: {hvs[0]}"
            print(f"{title}\n{'=' * len(title)}\n{info}")
    else:
        print(f"No API found for key={api_key} type={api_type}")


if __name__ == "__main__":
    main()
