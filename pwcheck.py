#!/usr/bin/env python3
"""pwcheck - a small password strength and breach checker.

Strength is estimated locally (length, character variety, common patterns).
Breach lookup uses the Have I Been Pwned "Pwned Passwords" range API with
k-anonymity: only the first 5 characters of the SHA-1 hash ever leave your
machine, never the password itself.
"""
import argparse
import getpass
import hashlib
import math
import re
import sys
import urllib.request

COMMON = {
    "password", "123456", "123456789", "qwerty", "abc123", "111111",
    "letmein", "admin", "welcome", "iloveyou", "monkey", "dragon",
}
SEQUENCES = ("abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiopasdfghjklzxcvbnm")


def charset_size(pw: str) -> int:
    size = 0
    if re.search(r"[a-z]", pw):
        size += 26
    if re.search(r"[A-Z]", pw):
        size += 26
    if re.search(r"[0-9]", pw):
        size += 10
    if re.search(r"[^a-zA-Z0-9]", pw):
        size += 33
    return size


def has_sequence(pw: str, n: int = 4) -> bool:
    low = pw.lower()
    for seq in SEQUENCES:
        for i in range(len(seq) - n + 1):
            chunk = seq[i:i + n]
            if chunk in low or chunk[::-1] in low:
                return True
    return False


def analyze(pw: str) -> dict:
    entropy = len(pw) * math.log2(charset_size(pw)) if pw else 0.0
    issues = []
    if len(pw) < 12:
        issues.append("Shorter than 12 characters")
    if pw.lower() in COMMON:
        issues.append("One of the most common passwords")
        entropy = min(entropy, 10)
    if re.search(r"(.)\1{2,}", pw):
        issues.append("Repeated characters (e.g. 'aaa')")
        entropy *= 0.8
    if has_sequence(pw):
        issues.append("Contains a keyboard or alphabet sequence")
        entropy *= 0.8
    if charset_size(pw) <= 26:
        issues.append("Uses only one type of character")

    if entropy < 28:
        rating = "Very weak"
    elif entropy < 36:
        rating = "Weak"
    elif entropy < 60:
        rating = "Reasonable"
    elif entropy < 80:
        rating = "Strong"
    else:
        rating = "Very strong"
    return {"entropy": round(entropy, 1), "rating": rating, "issues": issues}


def pwned_count(pw: str, timeout: float = 10.0) -> int:
    sha1 = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    req = urllib.request.Request(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"User-Agent": "pwcheck", "Add-Padding": "true"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        for line in resp.read().decode().splitlines():
            h, _, count = line.partition(":")
            if h == suffix:
                return int(count)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Check password strength and known breaches.")
    parser.add_argument("--offline", action="store_true", help="skip the breach lookup")
    args = parser.parse_args()

    pw = getpass.getpass("Password (hidden): ")
    if not pw:
        print("No password entered.")
        return 1

    result = analyze(pw)
    print(f"\nStrength : {result['rating']} (~{result['entropy']} bits)")
    for issue in result["issues"]:
        print(f"  - {issue}")

    if not args.offline:
        try:
            count = pwned_count(pw)
        except OSError as exc:
            print(f"\nBreach check failed: {exc}")
            return 2
        if count:
            print(f"\n[!] Found in {count:,} known breaches. Do not use this password.")
        else:
            print("\n[+] Not found in known breaches.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
