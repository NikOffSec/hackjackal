#!/usr/bin/env python3
"""Download the NVD CVE 2.0 JSON feeds and unzip them into data/.

python3 scripts/download_nvd.py                 every feed (a few GB unzipped)
python3 scripts/download_nvd.py modified        just what the app reads
python3 scripts/download_nvd.py recent 2024     any mix of feed names
"""

import argparse
import datetime
import io
import pathlib
import sys
import urllib.error
import urllib.request
import zipfile

BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0"
FIRST_YEAR = 2002
DATA_DIR = pathlib.Path(__file__).resolve().parent.parent / "data"


def all_feeds():
    this_year = datetime.date.today().year
    years = [str(y) for y in range(FIRST_YEAR, this_year + 1)]
    return ["modified", "recent"] + years


def fetch(url):
    # NVD turns away the default python user agent sometimes
    request = urllib.request.Request(url, headers={"User-Agent": "hackjackal"})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def download_feed(feed, out_dir):
    name = f"nvdcve-2.0-{feed}.json"
    print(f"{name}: downloading", flush=True)
    archive = fetch(f"{BASE_URL}/{name}.zip")

    target = out_dir / name
    partial = target.with_name(name + ".part")
    # only the expected file gets written, whatever else the zip says it has
    with zipfile.ZipFile(io.BytesIO(archive)) as zf:
        with zf.open(name) as src, open(partial, "wb") as dst:
            while chunk := src.read(1 << 20):
                dst.write(chunk)
    partial.replace(target)
    print(f"{name}: {target.stat().st_size / 1e6:.1f} MB unzipped", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "feeds", nargs="*", help="modified, recent or a year (default: all)"
    )
    parser.add_argument("--out", type=pathlib.Path, default=DATA_DIR)
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    failed = []
    for feed in args.feeds or all_feeds():
        try:
            download_feed(feed, args.out)
        except (urllib.error.URLError, zipfile.BadZipFile, KeyError, OSError) as e:
            print(f"{feed}: failed: {e}", file=sys.stderr)
            failed.append(feed)

    if failed:
        print(f"failed feeds: {' '.join(failed)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
