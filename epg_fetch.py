#!/usr/bin/env python3
import os
import sys
import re
import gzip
import hashlib
import urllib.request
import urllib.error
from urllib.parse import urlparse
from datetime import datetime, timedelta

# -------- Config --------
URLS_FILE = os.environ.get("EPG_URLS_FILE", "epg_urls.txt")
OUT_DIR = os.environ.get("EPG_OUT_DIR", ".")  # save in root
TIMEOUT = int(os.environ.get("EPG_TIMEOUT_SECONDS", "600"))
STAMP_FILENAMES = os.environ.get("EPG_STAMP_FILENAMES", "0") == "1"
DAYS_FORWARD = int(os.environ.get("EPG_DAYS_FORWARD", "1"))  # default 1 day
HOURS_PAST = int(os.environ.get("EPG_HOURS_PAST", "24"))     # default 24h back

# -------- Helpers --------
def read_urls(path: str):
    if not os.path.exists(path):
        print(f"[WARN] URLs file not found: {path}")
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]

def guess_filename_from_url(url: str) -> str:
    parsed = urlparse(url)
    name = os.path.basename(parsed.path)
    if not name:
        raw = (parsed.netloc + parsed.path).encode("utf-8", errors="ignore")
        h = hashlib.sha256(raw).hexdigest()[:16]
        name = f"epg_{h}.xml.gz"
    if not name.lower().endswith((".xml", ".xml.gz")):
        name += ".xml.gz"
    return name

def maybe_stamp_filename(basename: str) -> str:
    if not STAMP_FILENAMES:
        return basename
    if basename.lower().endswith(".xml.gz"):
        stem = basename[:-7]
        ext = ".xml.gz"
    else:
        stem, ext = os.path.splitext(basename)
    stamp = datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%SZ")
    return f"{stem}_{stamp}{ext}"

def is_gzip_bytes(b: bytes) -> bool:
    return len(b) >= 2 and b[0] == 0x1F and b[1] == 0x8B

def fetch_bytes(url: str, timeout: int = 45) -> bytes:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0", "Accept": "*/*"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()

def save_bytes(path: str, data: bytes):
    with open(path, "wb") as f:
        f.write(data)

# -------- XML Fixer & Filter --------
def fix_xml_issues(xml: str) -> str:
    xml = xml.replace("&amp;amp;", "&amp;")
    xml = re.sub(r"</programme>\s*<programme", "</programme>\n<programme", xml)
    xml = re.sub(r"[^\x20-\x7E]", "", xml)
    return xml

def filter_programmes(xml: str) -> str:
    """
    Keep programmes whose <start> time is within
    HOURS_PAST‒DAYS_FORWARD window.
    """
    now = datetime.utcnow()
    min_allowed = now - timedelta(hours=HOURS_PAST)
    max_allowed = now + timedelta(days=DAYS_FORWARD)

    patt = re.compile(
        r"(<programme\b[^>]*\bstart=\"(?P<start>\d{14})[^\"]*\"[^>]*>.*?</programme>)",
        flags=re.DOTALL,
    )

    def repl(match: re.Match) -> str:
        start_raw = match.group("start")          # 20250921090000…
        try:
            ts = datetime.strptime(start_raw, "%Y%m%d%H%M%S")
        except ValueError:
            return ""                             # bad timestamp → drop
        return match.group(0) if min_allowed <= ts <= max_allowed else ""

    return patt.sub(repl, xml)

    # Keep only <programme ...> ... </programme> blocks that match
    xml = re.sub(
        r"(<programme[^>]*start=\"(\d{14})[^\"]*\".*?</programme>)",
        lambda m: m.group(1) if keep(m) else "",
        xml,
        flags=re.DOTALL,
    )
    return xml

# -------- Main --------
def main():
    urls = read_urls(URLS_FILE)
    if not urls:
        print("[INFO] No URLs to fetch.")
        return 0

    now_ts = str(int(datetime.utcnow().timestamp()))
    ok = 0

    for url in urls:
        try:
            print(f"[INFO] Fetching: {url}")
            data = fetch_bytes(url, TIMEOUT)

            # Decide filename
            base = guess_filename_from_url(url)
            base = maybe_stamp_filename(base)
            out_path = os.path.join(OUT_DIR, base)

            # Decompress -> fix -> filter -> recompress
            if is_gzip_bytes(data):
                text = gzip.decompress(data).decode("utf-8", errors="ignore")
            else:
                text = data.decode("utf-8", errors="ignore")

            text = fix_xml_issues(text)
            text = filter_programmes(text)

            if base.lower().endswith(".xml.gz"):
                data = gzip.compress(text.encode("utf-8"), compresslevel=9)
            else:
                data = text.encode("utf-8")

            save_bytes(out_path, data)
            print(f"[OK] Saved -> {out_path}")
            ok += 1

        except Exception as e:
            print(f"[ERROR] Failed {url}: {e}")

    # Write/update a timestamp file in root
    try:
        with open(os.path.join(OUT_DIR, "last_updated_epg.txt"), "w") as f:
            f.write(now_ts + "\n")
    except Exception as e:
        print(f"[WARN] Could not write last-updated file: {e}")

    print(f"[DONE] {ok}/{len(urls)} fetched.")
    return 0 if ok > 0 else 1

if __name__ == "__main__":
    sys.exit(main())
