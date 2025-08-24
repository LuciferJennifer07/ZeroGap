import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import pyfiglet
import os

# ================= Banner Function =================
def banner():
    os.system("clear")
    ascii_banner = pyfiglet.figlet_format("ZeroGap")
    print("\033[1;32m" + ascii_banner + "\033[0m")
    print("\033[1;34m" + "="*50 + "\033[0m")
    print("\033[1;36m   🔒 Vulnerability Scanner Tool - Created by Yuvraj Tyagi 🔒   \033[0m")
    print("\033[1;34m" + "="*50 + "\033[0m\n")
# ====================================================

COMMON_PATHS = ["robots.txt", "admin/", "login/", "config/", "backup/", ".git/", "test/"]
HEADERS = {"User-Agent": "Mozilla/5.0 (Scanner by You)"}

def normalize_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    if not url.endswith("/"):
        url = url  # don't force slash; urljoin handles it
    return url

def check_site(url):
    url = normalize_url(url)
    print(f"\n[+] Checking site: {url}")
    try:
        response = requests.get(url, timeout=8, headers=HEADERS, allow_redirects=True)
        print(f"[+] Final URL: {response.url}")
        print(f"[+] Status Code: {response.status_code}")
    except Exception as e:
        print(f"[-] Could not reach the site: {e}")
        return

    if not response.url.startswith("https://"):
        print("[-] HTTPS not enabled — site may be insecure (or redirects to HTTP).")

    print("\n[+] Security Headers:")
    for header in ["Server", "X-Frame-Options", "Content-Security-Policy", "X-Content-Type-Options"]:
        value = response.headers.get(header)
        print(f"    {header}: {value if value else 'Missing!'}")

    if "Index of /" in response.text:
        print("[-] Directory listing is enabled — sensitive files might be exposed!")

    print("\n[+] Checking common paths:")
    for path in COMMON_PATHS:
        test_url = urljoin(response.url, path)
        try:
            r = requests.get(test_url, timeout=6, headers=HEADERS, allow_redirects=True)
            if r.status_code == 200:
                print(f"    Found (200): {test_url}")
            elif r.status_code in (301,302):
                print(f"    Redirects: {test_url} -> {r.headers.get('Location')}")
        except Exception:
            pass

    print("\n[+] Extracting some internal links (first 20):")
    soup = BeautifulSoup(response.text, "html.parser")
    count = 0
    for link in soup.find_all("a", href=True):
        full_link = urljoin(response.url, link['href'])
        if response.url.split("//")[1].split("/")[0] in full_link:
            print(f"    {full_link}")
            count += 1
            if count >= 20:
                break

# ================= Main =================
if __name__ == "__main__":
    banner()  # Banner call added here
    target_url = input("Enter the website URL (with or without http): ").strip()
    check_site(target_url)
