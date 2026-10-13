# Analysis: synthetic-02-fake-invoice-attachment.eml

Analyst: Waseem Akram Shaik | Date analyzed: 2026-10-12 | Sample type: synthetic

## 1. Summary
An email posing as a supplier's accounts receivable team claims invoice 88231 is 45 days overdue and tells the recipient to open an attached "PDF" to see payment details, threatening collections. The attachment is actually an HTML file with a double extension, the sender domain is a lookalike with a digit in place of a letter, and SPF, DKIM and DMARC all fail. Verdict: phishing with a malicious-attachment lure, high severity, high confidence.

## 2. Header analysis
| Field | Value | Observation |
|---|---|---|
| From (display name + address) | "Northwind Accounts Receivable" <billing@northwind-supp1ies[.]example> | Professional-sounding display name, but the domain contains the digit "1" in place of the letter "l". |
| Return-Path | billing@northwind-supp1ies[.]example | Same domain as From, so this sample does not use mismatched domains. The attacker relies on the lookalike domain alone. |
| Reply-To | Not present | Replies would go to the From address. |
| SPF result | softfail (203.0.113.88 not designated by the domain) | The sending IP is not authorized by the domain's SPF record. Softfail means the domain owner marked it suspicious but not strictly forbidden. |
| DKIM result | fail (signature verification failed) | A signature is present but does not validate, so the message was altered or signed with the wrong key. |
| DMARC result | fail (p=none) | Both SPF and DKIM fail, so DMARC fails. The policy is p=none, so the gateway flags but does not block. |
| Originating IP (bottom Received hop) | 203.0.113.88 | The only external hop. It connected from `mx-out[.]northwind-supp1ies[.]example`. |
| Do From / Return-Path / Reply-To domains match? | From and Return-Path match; no Reply-To | Matching domains here only prove the attacker controls the lookalike domain. They do not make the message legitimate. |

Received chain notes (oldest hop first):
1. 09:41:05 UTC: `mx-out[.]northwind-supp1ies[.]example` (203.0.113.88) delivered the message to the recipient organization's gateway `mail-gw[.]contoso-logistics[.]example`.
2. 09:41:07 UTC: the gateway (private address 10.20.0.5) passed it to the internal mailbox server `mbx01`.

## 3. Sender and domain
- Domain(s) examined (defanged): `northwind-supp1ies[.]example`
- Lookalike or typo-squat? Yes. "supp1ies" replaces the letter "l" (fifth character) with the digit "1". In many fonts the two look almost identical. The brand name "Northwind" is a plausible supplier name, which makes the message believable to an accounts payable team.
- WHOIS / registration date (real samples only): N/A. `.example` is a reserved top-level domain (RFC 2606).
- IP reputation (real samples only): N/A. 203.0.113.88 belongs to a documentation range (RFC 5737, TEST-NET-3).

## 4. Links
| Display text | Real target (defanged) | Match? | Scan result (real samples only) |
|---|---|---|---|
| None | N/A | N/A | N/A |

The message body contains no links. The risk is delivered through the attachment.

## 5. Attachments
| File name | Type / extension trick? | SHA-256 | Lookup result |
|---|---|---|---|
| Invoice_88231.pdf.html | Yes. Double extension: it looks like a PDF but the real type is HTML (Content-Type text/html). | 95e58c8b1fc09a8df464f2fabf5f244ac17dd2c28c6ee7145069012b70374074 | N/A for this synthetic file (a harmless placeholder, 151 bytes) |

Why this matters: HTML attachments can contain a fake login form or script that runs in the browser and can send entered credentials to an attacker. Attackers use the `.pdf.html` name so the "pdf" part is what the recipient notices.

## 6. Content and social-engineering cues
- Urgency / threat: "45 days overdue", "final notice", "sent to collections" if not paid today.
- Request (credentials, payment, gift cards, click, open file): open the attached document and follow its instructions to view payment details.
- Greeting / tone / grammar: generic "Dear Customer" (no company or person named), even though the mail was sent to the accounts payable mailbox. Grammar is clean.
- Impersonated entity: a supplier ("Northwind Accounts Receivable"). The target is a finance function, which handles invoices routinely and is under pressure to pay on time.

## 7. Verdict
- Classification: phishing, malicious attachment lure
- Severity: high   Confidence: high
- Evidence supporting the verdict:
  - SPF softfail, DKIM fail and DMARC fail on a lookalike domain (sections 2 and 3).
  - The attachment `Invoice_88231.pdf.html` uses a double extension to disguise an HTML file as a PDF (section 5).
  - Generic greeting plus an overdue and collections threat aimed at accounts payable (section 6).
- MITRE ATT&CK mapping: T1566.001, Phishing: Spearphishing Attachment

## 8. Recommended response for this email
- Block the sender domain `northwind-supp1ies[.]example` and address `billing@northwind-supp1ies[.]example` at the mail gateway.
- Quarantine or strip HTML attachments with double extensions, and block the file hash on endpoints.
- Search all mailboxes for the subject "OVERDUE: Invoice 88231 - final notice" and purge matching messages.
- If anyone opened the attachment: isolate the device, run an endpoint scan, reset any credentials entered and review sign-in logs.
- Remind the accounts payable team to verify invoice and payment requests against vendor records, using contact details already on file and not the ones in the email.
