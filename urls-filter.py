#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, requests, threading, os, re, ssl, urllib3
from termcolor import colored
from queue import Queue

# ---------------- CONFIG ----------------
THREADS = 10
COLOR = "magenta"
GF_PATH = "./gf-templates/"
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------- FUNCTIONS ----------------

def check_http_https(url):
    """Check if URL uses HTTP instead of HTTPS"""
    if url.startswith("http://"):
        return True
    return False

def check_ssl(url):
    """Check SSL/TLS issues"""
    try:
        if not url.startswith("https://"):
            return "No HTTPS"
        r = requests.get(url, verify=True, timeout=5)
        return "HTTPS OK"
    except requests.exceptions.SSLError:
        return "SSL Error"
    except requests.exceptions.RequestException:
        return "Request Failed"

def check_sensitive_params(url):
    """Check sensitive params like password, token in URL"""
    sensitive_keywords = ["password", "token", "api_key", "auth", "session"]
    for k in sensitive_keywords:
        if k in url.lower():
            return True
    return False

def gf_scan(url, gf_folder):
    """Check GF templates matches"""
    matches = []
    if not os.path.exists(gf_folder):
        return matches
    for file in os.listdir(gf_folder):
        path = os.path.join(gf_folder, file)
        with open(path, "r", errors="ignore") as f:
            patterns = f.read().splitlines()
            for p in patterns:
                if re.search(p, url):
                    matches.append(file)
    return matches

def scan_worker(q, results, gf_folder, debug):
    while not q.empty():
        url = q.get()
        weak_flags = []
        # 1. Protocol check
        if check_http_https(url):
            weak_flags.append("HTTP")

        # 2. SSL/TLS check
        ssl_status = check_ssl(url)
        if ssl_status != "HTTPS OK":
            weak_flags.append(ssl_status)

        # 3. Sensitive params
        if check_sensitive_params(url):
            weak_flags.append("Sensitive Params")

        # 4. GF scan
        gf_matches = gf_scan(url, gf_folder)
        if gf_matches:
            weak_flags.append("GF Match: " + ",".join(gf_matches))

        # 5. Store results if weak
        if weak_flags:
            results.append((url, weak_flags))
            if debug:
                print(colored(f"[DEBUG] {url} => {weak_flags}", "yellow"))
        q.task_done()

def scan_urls(urls, threads, gf_folder, debug, silent):
    q = Queue()
    results = []
    for u in urls:
        q.put(u)
    for i in range(threads):
        t = threading.Thread(target=scan_worker, args=(q, results, gf_folder, debug))
        t.daemon = True
        t.start()
    q.join()
    weak_urls = [u for u,_ in results]
    return weak_urls, results

def dashboard(weak_urls, gf_results, total, color, silent):
    if silent: return
    print(colored("\n===== Weak URL Scanner Dashboard =====", color))
    print(colored(f"Total URLs scanned: {total}", color))
    print(colored(f"Weak URLs found: {len(weak_urls)}", color))
    for url, flags in gf_results:
        print(colored(f"{url} => {', '.join(flags)}", color))
    print(colored("=====================================", color))

# ---------------- MAIN ----------------

def main():
    parser = argparse.ArgumentParser(description="Ultra Advanced Weak URL Scanner + Security Checker")
    parser.add_argument("-l", "--list", help="Target URLs file", required=True)
    parser.add_argument("-o", "--output", help="Output file prefix", default="output")
    parser.add_argument("--gf", help="GF templates folder", default=GF_PATH)
    parser.add_argument("-t", "--threads", type=int, help="Number of threads", default=THREADS)
    parser.add_argument("--silent", action="store_true", help="Silent mode, hide progress bar and logs")
    parser.add_argument("--debug", action="store_true", help="Debug mode, show detailed request/response logs")
    parser.add_argument("--color", default=COLOR, help="Dashboard color (termcolor supported)")
    parser.add_argument("--auto", action="store_true", help="Automatically run all checks and optimizations")
    args = parser.parse_args()

    # Auto mode settings
    if args.auto:
        print(colored("[*] Auto mode enabled: Running all checks with optimal settings...", COLOR))
        args.debug = False
        args.silent = False
        args.threads = THREADS
        args.gf = GF_PATH

    with open(args.list, "r") as f:
        urls = f.read().splitlines()

    weak_urls, gf_results = scan_urls(urls, args.threads, args.gf, args.debug, args.silent)
    dashboard(weak_urls, gf_results, len(urls), args.color, args.silent)

    # Save outputs
    weak_file = f"{args.output}_weak_urls.txt"
    gf_file = f"{args.output}_gf_matched.txt"
    with open(weak_file, "w") as f:
        for u in weak_urls: f.write(u+"\n")
    with open(gf_file, "w") as f:
        for u, flags in gf_results: f.write(f"{u} => {','.join(flags)}\n")

    if not args.silent:
        print(colored(f"\n[+] Saved weak URLs in {weak_file}", args.color))
        print(colored(f"[+] Saved GF matched URLs in {gf_file}", args.color))

if __name__ == "__main__":
    main()
