#!/usr/bin/env python3
import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import pyfiglet
import os
import sys
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ================== Banner ==================
import os
import pyfiglet

def show_banner(tool_name="ZeroGap"):
    # clear screen (POSIX -> clear, Windows -> cls)
    os.system("clear" if os.name == "posix" else "cls")

    # try pyfiglet; fallback to plain text if pyfiglet not available
    try:
        ascii_art = pyfiglet.figlet_format(tool_name)
        print("\033[92m" + ascii_art + "\033[0m")   # green
    except Exception:
        print("*** ZeroGap ***")   # guaranteed fallback

    print("\033[94m" + "="*72 + "\033[0m")
    print("\033[96m   🔒 Vulnerability Scanner Tool - Created by Yuvraj Tyagi 🔒   \033[0m")
    print("\033[94m" + "="*72 + "\033[0m\n")


# ============================================

DEFAULT_PATHS = [
    "robots.txt", "admin/", "login/", "config/", 
    "backup/", ".git/", "test/"
]
DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 (Security Scanner)"}


def normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def parse_status_filter(spec):
    if not spec:
        return None
    result = set()
    for part in [p.strip() for p in spec.split(",") if p.strip()]:
        if "-" in part:
            try:
                start, end = map(int, part.split("-", 1))
                for code in range(min(start, end), max(start, end) + 1):
                    result.add(code)
            except:
                continue
        else:
            try:
                result.add(int(part))
            except:
                continue
    return result


def load_paths_file(pathfile):
    try:
        with open(pathfile, "r") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except Exception as e:
        print(f"[-] Could not read paths file: {e}")
        return []


def check_single_path(base_url, path, headers, timeout):
    url = urljoin(base_url, path)
    try:
        r = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True)
        return (url, r.status_code, r.headers, r.url, None)
    except Exception as e:
        return (url, None, None, None, str(e))


def scan_target(target, paths, headers, timeout, link_limit, threads, status_filter, csv_writer, logfile):
    url = normalize_url(target)
    now = datetime.utcnow().isoformat()

    log = (lambda s: logfile.write(s + "\n")) if logfile else (lambda s: None)

    print(f"\n[+] Scanning: {url}")
    log(f"[{now}] Target: {url}")

    try:
        resp = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True)
        print(f"[+] Final URL: {resp.url}")
        print(f"[+] Status: {resp.status_code}")
    except Exception as e:
        print(f"[-] Could not reach site: {e}")
        log(f"[{now}] Connection failed: {e}")
        return

    if not resp.url.startswith("https://"):
        print("[-] Warning: HTTPS not enabled or redirecting to HTTP")
        log(f"[{now}] HTTPS missing or redirect issue.")

    # --- Security Headers ---
    print("\n[+] Security Headers:")
    for h in ["Server", "X-Frame-Options", "Content-Security-Policy", "X-Content-Type-Options"]:
        v = resp.headers.get(h, "Missing!")
        print(f"    {h}: {v}")
        log(f"[{now}] Header {h}: {v}")

    if "Index of /" in resp.text:
        print("[-] Directory listing seems enabled!")
        log(f"[{now}] Directory listing likely enabled.")

    # --- Path Checking ---
    print(f"\n[+] Checking common paths ({threads} threads):")
    with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        futures = {ex.submit(check_single_path, resp.url, p, headers, timeout): p for p in paths}
        for fut in as_completed(futures):
            test_url, status, hdrs, final, err = fut.result()
            if err:
                log(f"[{now}] Path error {test_url}: {err}")
                continue

            if status_filter and status not in status_filter:
                continue

            if status == 200:
                print(f"    [200] Found: {test_url}")
            elif status in (301, 302):
                print(f"    [{status}] Redirect: {test_url} -> {hdrs.get('Location','?')}")
            else:
                print(f"    [{status}] {test_url}")

            if csv_writer:
                csv_writer.writerow([
                    url, test_url, status, final,
                    hdrs.get("Server") if hdrs else None,
                    hdrs.get("X-Frame-Options") if hdrs else None,
                    err or ""
                ])

    # --- Extract Internal Links ---
    print(f"\n[+] Extracting up to {link_limit} internal links:")
    soup = BeautifulSoup(resp.text, "html.parser")
    base_host = resp.url.split("//")[1].split("/")[0]
    count = 0
    for a in soup.find_all("a", href=True):
        full = urljoin(resp.url, a["href"])
        if base_host in full:
            print(f"    {full}")
            log(f"[{now}] Link: {full}")
            count += 1
            if count >= link_limit:
                break


def parse_args():
    p = argparse.ArgumentParser(
        prog="VulnHawk",
        description="Lightweight vulnerability scanner with threading, filters, and logging."
    )
    p.add_argument("-u", "--url", help="Target URL")
    p.add_argument("-f", "--file", help="File with multiple targets")
    p.add_argument("-p", "--paths", help="Custom paths (comma separated)")
    p.add_argument("-P", "--paths-file", help="File with custom paths")
    p.add_argument("-t", "--timeout", type=float, default=8.0, help="Request timeout (default: 8s)")
    p.add_argument("-l", "--links", type=int, default=20, help="Max internal links to show")
    p.add_argument("--threads", type=int, default=5, help="Number of threads (default: 5)")
    p.add_argument("--status", help="Status codes filter (e.g. 200,301,400-499)")
    p.add_argument("--output", help="CSV output file")
    p.add_argument("--log", help="Log file")
    p.add_argument("--no-banner", action="store_true", help="Disable banner")
    p.add_argument("--name", default="VulnHawk", help="Banner name (default: VulnHawk)")
    return p.parse_args()


def main():
    args = parse_args()

    # Banner
    if not args.no_banner:
        show_banner(args.name)

    # Build path list
    paths = DEFAULT_PATHS.copy()
    if args.paths_file:
        custom = load_paths_file(args.paths_file)
        if custom: paths = custom
    elif args.paths:
        custom = [p.strip() for p in args.paths.split(",") if p.strip()]
        if custom: paths = custom

    # CSV setup
    csv_writer = None
    csv_file = None
    if args.output:
        new_file = not os.path.exists(args.output)
        csv_file = open(args.output, "a", newline="", encoding="utf-8")
        csv_writer = csv.writer(csv_file)
        if new_file:
            csv_writer.writerow(["target", "tested_path", "status", "final_url", "server", "x_frame", "note"])

    # Log setup
    logfile = None
    if args.log:
        logfile = open(args.log, "a", encoding="utf-8")
        logfile.write(f"\n--- Scan started {datetime.utcnow().isoformat()} UTC ---\n")

    # Status filter
    status_filter = parse_status_filter(args.status)

    # Targets
    targets = []
    if args.file:
        try:
            with open(args.file) as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[-] Could not read targets file: {e}")
            sys.exit(1)
    elif args.url:
        targets = [args.url.strip()]
    else:
        url = input("Enter target URL: ").strip()
        if url: targets = [url]

    # Run
    for t in targets:
        scan_target(t, paths, DEFAULT_HEADERS, args.timeout, args.links, args.threads, status_filter, csv_writer, logfile)

    # Cleanup
    if csv_file: csv_file.close()
    if logfile: logfile.close()


if __name__ == "__main__":
    main()
