# Analysis: synthetic-05-legitimate-it-notice.eml

Analyst: Waseem Akram Shaik | Date analyzed: 2026-10-12 | Sample type: synthetic

## 1. Summary
An internal IT Service Desk email reminds the recipient that a scheduled 90-day password rotation is due in 3 days and links to the company's own single sign-on page. Despite an "URGENT" subject line, authentication fully passes with a strict DMARC policy, the message travelled only through internal relays, and the link stays on the company domain. Verdict: legitimate, low severity, medium-high confidence.

## 2. Header analysis
| Field | Value | Observation |
|---|---|---|
| From (display name + address) | "Contoso IT Service Desk" <servicedesk@contoso-logistics[.]example> | Same domain as the recipient's organization. |
| Return-Path | servicedesk@contoso-logistics[.]example | Matches From. |
| Reply-To | Not present | |
| SPF result | pass | Aligned with the organization's domain. |
| DKIM result | pass (contoso-logistics[.]example) | Valid signature from the same domain. |
| DMARC result | pass (p=reject) | Aligned, and the domain enforces a strict policy, meaning spoofed mail from it would be rejected. |
| Originating IP (bottom Received hop) | 10.20.0.25 (private) | Internal relay `smtp-relay[.]contoso-logistics[.]example`. No external hops. |
| Do From / Return-Path / Reply-To domains match? | Yes (no Reply-To) | Consistent. |

Received chain notes (oldest hop first):
1. 08:00:04 UTC: internal relay `smtp-relay[.]contoso-logistics[.]example` (10.20.0.25) delivered to `mbx01`.
2. 08:00:06 UTC: `mbx01` (10.20.0.30) passed it to `mbx02`, the recipient's mailbox server.

## 3. Sender and domain
- Domain(s) examined (defanged): `contoso-logistics[.]example`, `sso[.]contoso-logistics[.]example`
- Lookalike or typo-squat? No. The domain matches the recipient organization's own domain exactly.
- WHOIS / registration date (real samples only): N/A. Reserved domain.
- IP reputation (real samples only): N/A. Both hops use private (RFC 1918) addresses.

## 4. Links
| Display text | Real target (defanged) | Match? | Scan result (real samples only) |
|---|---|---|---|
| hxxps://sso[.]contoso-logistics[.]example/password | hxxps://sso[.]contoso-logistics[.]example/password | Yes | N/A (synthetic) |

The link is plain text and stays on the company domain.

## 5. Attachments
| File name | Type / extension trick? | SHA-256 | Lookup result |
|---|---|---|---|
| None | N/A | N/A | N/A |

## 6. Content and social-engineering cues
- Urgency / threat: "URGENT" in the subject and a 3-day expiry. Both are mild and tied to a routine schedule rather than a threat of loss.
- Request (credentials, payment, gift cards, click, open file): change the password through the company SSO page.
- Greeting / tone / grammar: generic greeting, but the message states that IT will never ask for a password by email or phone and points to the ticket portal and intranet.
- Impersonated entity: none, it is the real IT department.

## 7. Verdict
- Classification: legitimate
- Severity: low   Confidence: medium-high
- Evidence supporting the verdict:
  - SPF, DKIM and DMARC all pass and align, with DMARC at p=reject (section 2).
  - Internal-only relay path and an unmodified, same-domain link (sections 2 and 4).
  - Urgency is routine and the message gives safe-handling guidance (section 6).
- Caution: "URGENT" wording is a reason to verify, not proof of phishing. Best practice is still to open the SSO page by typing the address or using a bookmark, not by clicking the email link. Confidence stays below "high" because I judged only the file contents.

## 8. Recommended response for this email
- No block or purge action.
- Do not add any indicator to blocklists.
- Use as a baseline example in awareness training of what a legitimate notice looks like, including the "we will never ask" statement.
- Suggest the IT team avoid "URGENT" on routine reminders, since it trains users to ignore real urgency signals.
