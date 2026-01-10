<img width="1536" height="1024" alt="1000104260" src="https://github.com/user-attachments/assets/36ce6d6c-8c68-4cc0-9da2-a435bf3b17b2" />
============================================================
           🛠️  WEAK-URLS-FINDER: README  🛠️
============================================================

Weak-URLs-Finder ek high-performance, autonomous, aur deep-security 
scanning tool hai. Ye tool specifically penetration testers aur bug 
bounty hunters ke liye banaya gaya hai taaki wo hazaron URLs mein 
se "Weak Links" ko seconds mein dhoond sakein.

------------------------------------------------------------
🌟 KEY FEATURES (Advanced)
------------------------------------------------------------
1. Multi-OS Support: Kali Linux, Termux, aur macOS par fully tested.
2. Memory-Mapped Scanning: GF patterns ko RAM mein cache karta hai, 
   jisse scanning speed 10x badh jati hai.
3. WAF Bypass (Stealth): Random User-Agents aur custom headers ka 
   use karta hai taaki security firewalls ise block na karein.
4. Autonomous Reporting: Har scan ke baad timestamped report 
   auto-generate karta hai.
5. Deep Analysis: 
   - SSL/TLS configuration checks.
   - Missing Security Headers (e.g., Clickjacking protection).
   - Sensitive Parameter Detection (Regex based).
   - Pattern Matching via GF Templates.

------------------------------------------------------------
🚀 INSTALLATION
------------------------------------------------------------

# 1. Repository ko clone karein ya file save karein.
# 2. Required libraries install karein:
pip install requests termcolor urllib3

# 3. GF Templates folder banayein (optional, tool khud bhi bana lega):
mkdir gf-templates

------------------------------------------------------------
💻 USAGE (Commands)
------------------------------------------------------------

Basic Scan:
python3 weak-urls-finder.py -l target_urls.txt

Advanced Scan (Custom Threads & Output):
python3 weak-urls-finder.py -l urls.txt -t 50 -o my_scan_results

Help Menu:
python3 weak-urls-finder.py --help

------------------------------------------------------------
📂 DIRECTORY STRUCTURE
------------------------------------------------------------
.
├── weak-urls-finder.py    # Main Tool
├── gf-templates/          # Put your .json or .txt patterns here
├── target_urls.txt        # Your list of URLs to scan
└── scan_result_*.txt      # Auto-generated reports

------------------------------------------------------------
⚠️ DISCLAIMEER
------------------------------------------------------------
Ye tool sirf educational purposes aur authorized security testing 
ke liye hai. Kisi bhi system par bina permission scan karna illegal 
hai. Developer ki koi zimmedari nahi hogi.

------------------------------------------------------------
Maintainer: [ManageKali Team]
Version: 2.0 (Autonomous Edition)
============================================================
