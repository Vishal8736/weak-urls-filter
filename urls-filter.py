#!/usr/bin/env python3
import argparse, requests, threading, os, re, ssl, urllib3, random
from termcolor import colored
from queue import Queue
from datetime import datetime

# ---------------- CONFIG ----------------
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
]

class WeakURLsFinder:
    def __init__(self, threads, gf_path, output_prefix):
        self.threads = threads
        self.gf_path = gf_path
        self.output_prefix = output_prefix
        self.results = []
        self.patterns = self._load_gf_patterns()
        self.q = Queue()

    def _load_gf_patterns(self):
        """Patterns ko memory me load karta hai speed ke liye"""
        cached_patterns = {}
        if os.path.exists(self.gf_path):
            for file in os.listdir(self.gf_path):
                with open(os.path.join(self.gf_path, file), "r", errors="ignore") as f:
                    cached_patterns[file] = [line.strip() for line in f if line.strip()]
        return cached_patterns

    def deep_scan(self, url):
        flags = []
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        
        try:
            # 1. Protocol & SSL Deep Check
            if url.startswith("http://"):
                flags.append("INSECURE_HTTP")
            
            response = requests.get(url, headers=headers, verify=False, timeout=7)
            
            # 2. Security Headers Check
            if 'X-Frame-Options' not in response.headers:
                flags.append("MISSING_CLICKJACKING_PROTECTION")
            
            # 3. Sensitive Params (Regex based)
            sensitive_regex = r"(password|token|api_key|secret|auth|session|admin|aws_|db_)"
            if re.search(sensitive_regex, url, re.IGNORECASE):
                flags.append("SENSITIVE_PARAM_LEAK")

            # 4. Memory-Based GF Match (Lightning Fast)
            for filename, regex_list in self.patterns.items():
                for p in regex_list:
                    if re.search(p, url):
                        flags.append(f"GF:{filename}")
                        break

        except Exception as e:
            flags.append(f"SCAN_ERROR:{type(e).__name__}")
        
        return flags

    def worker(self):
        while not self.q.empty():
            url = self.q.get()
            found_flags = self.deep_scan(url)
            if found_flags:
                self.results.append((url, found_flags))
                print(colored(f"[!] Vulnerable: {url} -> {', '.join(found_flags)}", "magenta"))
            self.q.task_done()

    def start(self, urls):
        print(colored(f"[*] Starting Deep Scan on {len(urls)} targets...", "cyan"))
        for u in urls: self.q.put(u)
        
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
        self.q.join()
        self.save_reports()

    def save_reports(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name = f"{self.output_prefix}_vulnerabilities_{timestamp}.txt"
        with open(report_name, "w") as f:
            for url, flags in self.results:
                f.write(f"URL: {url} | Risks: {', '.join(flags)}\n")
        print(colored(f"\n[+] Autonomous Report Generated: {report_name}", "green"))

# ---------------- MAIN ----------------

def main():
    parser = argparse.ArgumentParser(description="Weak-URLs-Finder: Advanced Autonomous Security Scanner")
    parser.add_argument("-l", "--list", help="Target URLs file", required=True)
    parser.add_argument("-t", "--threads", type=int, default=15)
    parser.add_argument("--gf", default="./gf-templates/")
    parser.add_argument("-o", "--output", default="scan_result")
    args = parser.parse_args()

    # Autonomous folder creation
    if not os.path.exists(args.gf):
        os.makedirs(args.gf)
        print(colored("[*] Created missing GF templates folder.", "yellow"))

    if not os.path.exists(args.list):
        print(colored("[ERROR] URL list file not found!", "red"))
        return

    with open(args.list, "r") as f:
        urls = [line.strip() for line in f if line.strip()]

    scanner = WeakURLsFinder(args.threads, args.gf, args.output)
    scanner.start(urls)

if __name__ == "__main__":
    main()

