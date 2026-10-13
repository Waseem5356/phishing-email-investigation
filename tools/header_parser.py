#!/usr/bin/env python3
"""
header_parser.py - small helper that summarizes a .eml file for phishing triage.

It does NOT open links or attachments. It only reads the file, prints the key
header fields, lists the Received chain (oldest hop first), extracts URLs
(defanged), and prints SHA-256 hashes of any attachments.

Usage:  python3 tools/header_parser.py samples/synthetic-01-credential-harvest.eml
Only claim this script on your resume if you read it, understand it, and can
explain every line.
"""
import email
import hashlib
import re
import sys
from email import policy

URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)


def defang(url: str) -> str:
    url = url.replace("http", "hxxp", 1) if url.lower().startswith("http") else url
    return url.replace(".", "[.]")


def main(path: str) -> None:
    with open(path, "rb") as fh:
        msg = email.message_from_binary_file(fh, policy=policy.default)

    print(f"=== {path} ===")
    for field in ("From", "Return-Path", "Reply-To", "To", "Subject", "Date", "Message-ID"):
        print(f"{field:12}: {msg.get(field)}")

    print("\n--- Authentication-Results ---")
    print(msg.get("Authentication-Results", "(none)"))

    print("\n--- Received chain (oldest hop first) ---")
    hops = msg.get_all("Received", [])
    for i, hop in enumerate(reversed(hops), 1):
        print(f"{i}. {' '.join(str(hop).split())}")

    urls, attachments = set(), []
    for part in msg.walk():
        ctype = part.get_content_type()
        if part.get_filename():
            payload = part.get_payload(decode=True) or b""
            attachments.append((part.get_filename(), hashlib.sha256(payload).hexdigest(), len(payload)))
        elif ctype in ("text/plain", "text/html"):
            text = part.get_content()
            urls.update(URL_RE.findall(text))

    print("\n--- URLs found (defanged) ---")
    for u in sorted(urls):
        print(defang(u))
    if not urls:
        print("(none)")

    print("\n--- Attachments ---")
    for name, digest, size in attachments:
        print(f"{name} | {size} bytes | sha256={digest}")
    if not attachments:
        print("(none)")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python3 tools/header_parser.py <file.eml>")
    main(sys.argv[1])
