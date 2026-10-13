# Analysis: synthetic-04-parcel-redelivery-short-link.eml

Analyst: Waseem Akram Shaik | Date analyzed: 2026-10-12 | Sample type: synthetic

## 1. Summary
A fake delivery notice says a parcel could not be delivered and demands a $1.99 redelivery fee within 24 hours, using a shortened link that hides the destination. SPF softfails, DKIM is absent and no DMARC record exists. The sender is a generic tracking-themed domain tied to no known carrier. Verdict: phishing (payment and personal data harvesting), medium-high severity, medium-high confidence.

## 2. Header analysis
| Field | Value | Observation |
|---|---|---|
| From (display name + address) | "ParcelTrack Delivery" <notify@parcel-tracking-center[.]example> | A generic, brand-like name with no link to a known carrier. |
| Return-Path | notify@parcel-tracking-center[.]example | Matches From. |
| Reply-To | Not present | |
| SPF result | softfail (203.0.113.150) | The sending IP is not authorized by the domain. |
| DKIM result | none | Not signed. |
| DMARC result | none (no DMARC record) | The domain publishes no policy, so receivers have no instruction on what to do with spoofed mail. |
| Originating IP (bottom Received hop) | 203.0.113.150 | `relay3[.]parcel-tracking-center[.]example`. |
| Do From / Return-Path / Reply-To domains match? | From and Return-Path match; no Reply-To | No mismatch, but no authentication either. |

Received chain notes (oldest hop first):
1. 11:27:17 UTC: `relay3[.]parcel-tracking-center[.]example` (203.0.113.150) delivered the message to `mail-gw[.]contoso-logistics[.]example`.
2. 11:27:19 UTC: the gateway (10.20.0.5) passed it to `mbx01`.

## 3. Sender and domain
- Domain(s) examined (defanged): `parcel-tracking-center[.]example`, `shrt[.]example`
- Lookalike or typo-squat? Not a typo of a specific carrier. It is a generic "tracking center" name designed to sound official without naming a real company, which avoids brand-matching checks.
- WHOIS / registration date (real samples only): N/A. Reserved domain. On a real sample, a domain registered days ago would be a strong signal.
- IP reputation (real samples only): N/A. 203.0.113.150 is in a documentation range.

## 4. Links
| Display text | Real target (defanged) | Match? | Scan result (real samples only) |
|---|---|---|---|
| Reschedule delivery | hxxps://shrt[.]example/aB3dE9 | Cannot be verified | N/A (synthetic) |

The link uses a URL shortener, so the final destination is hidden. On a real sample I would expand it safely with urlscan.io or VirusTotal without visiting it.

## 5. Attachments
| File name | Type / extension trick? | SHA-256 | Lookup result |
|---|---|---|---|
| None | N/A | N/A | N/A |

## 6. Content and social-engineering cues
- Urgency / threat: parcel "returned within 24 hours" unless action is taken.
- Request (credentials, payment, gift cards, click, open file): click the link, confirm details and pay a $1.99 fee.
- Greeting / tone / grammar: generic "Dear customer", an invented tracking number and a small fee. The small amount lowers suspicion, and the goal is usually card data.
- Impersonated entity: a delivery company (unnamed brand).

## 7. Verdict
- Classification: phishing (payment and data harvesting)
- Severity: medium-high   Confidence: medium-high
- Evidence supporting the verdict:
  - SPF softfail, no DKIM and no DMARC, so there is no authentication at all (section 2).
  - A shortened link hides the destination, and the fee-plus-deadline pressure is a known parcel-scam pattern (sections 4 and 6).
  - A generic sender domain tied to no known carrier (section 3).
- Limitation: the link cannot be expanded because the domains are reserved test domains, so the confidence is not "high".
- MITRE ATT&CK mapping: T1566.002, Phishing: Spearphishing Link

## 8. Recommended response for this email
- Block `parcel-tracking-center[.]example` and the shortener link `hxxps://shrt[.]example/aB3dE9`.
- Search mailboxes for the subject "Delivery attempt failed - reschedule now" and purge matches.
- If anyone clicked or paid, advise contacting their card issuer and resetting any reused passwords.
- Consider blocking or rewriting URL-shortener links at the gateway, and remind users to check delivery status on the carrier's official site or app.
