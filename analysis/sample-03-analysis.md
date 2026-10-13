# Analysis: synthetic-03-ceo-fraud-bec.eml

Analyst: Waseem Akram Shaik | Date analyzed: 2026-10-12 | Sample type: synthetic

## 1. Summary
An email appearing to come from the company CEO asks a finance mailbox to quietly buy six $200 gift cards and reply with the card numbers and PINs. It passes SPF, DKIM and DMARC, but only because it was sent from a free-mail provider, not from the company's domain. The request, secrecy and urgency match business email compromise (CEO impersonation). Verdict: BEC / impersonation, high severity, medium-high confidence.

## 2. Header analysis
| Field | Value | Observation |
|---|---|---|
| From (display name + address) | "Karen Whitfield (CEO)" <karen.whitfield.ceo@freemail-provider[.]example> | An executive title in the display name, but the address is on a free-mail domain, not the company domain. |
| Return-Path | karen.whitfield.ceo@freemail-provider[.]example | Matches From. |
| Reply-To | k.whitfield.private@secure-inbox[.]example | A different domain. Replies would go to an address the attacker controls. |
| SPF result | pass (198.51.100.120) | Passes for the free-mail provider's own domain. Only proves the provider sent it. |
| DKIM result | pass (freemail-provider[.]example) | Valid signature from the provider. Proves the provider signed it, not that the CEO wrote it. |
| DMARC result | pass (p=none) | Aligned with the From domain, which is the free-mail provider. Authentication is accurate but irrelevant to who the sender really is. |
| Originating IP (bottom Received hop) | 198.51.100.120 | Provider mail server `mta12[.]freemail-provider[.]example`. |
| Do From / Return-Path / Reply-To domains match? | From and Return-Path match; Reply-To differs | The Reply-To switch is a classic BEC sign. |

Received chain notes (oldest hop first):
1. 15:02:42 UTC: `mta12[.]freemail-provider[.]example` (198.51.100.120) delivered the message to `mail-gw[.]contoso-logistics[.]example`.
2. 15:02:44 UTC: the gateway (10.20.0.5) passed it to the internal mailbox server `mbx01`.

## 3. Sender and domain
- Domain(s) examined (defanged): `freemail-provider[.]example`, `secure-inbox[.]example`
- Lookalike or typo-squat? Not a typo-squat. The attack uses a free-mail account with the CEO's name instead of spoofing the company domain. A real CEO would normally email from the company domain.
- WHOIS / registration date (real samples only): N/A. `.example` is reserved (RFC 2606).
- IP reputation (real samples only): N/A. 198.51.100.120 is in a documentation range (RFC 5737).

## 4. Links
| Display text | Real target (defanged) | Match? | Scan result (real samples only) |
|---|---|---|---|
| None | N/A | N/A | N/A |

No links or attachments. This is pure social engineering, which is why URL and attachment scanning would find nothing.

## 5. Attachments
| File name | Type / extension trick? | SHA-256 | Lookup result |
|---|---|---|---|
| None | N/A | N/A | N/A |

## 6. Content and social-engineering cues
- Urgency / threat: "heading into a board meeting", "quickly", "today".
- Request (credentials, payment, gift cards, click, open file): buy six $200 gift cards and reply with card numbers and PINs.
- Greeting / tone / grammar: short and casual, "Sent from my mobile" signature to excuse brevity, and "keep this between us" to stop verification.
- Impersonated entity: the CEO, sent to a finance operations mailbox.

## 7. Verdict
- Classification: BEC / executive impersonation
- Severity: high   Confidence: medium-high
- Evidence supporting the verdict:
  - An executive title sent from a free-mail address, with a Reply-To on a different domain (section 2).
  - A gift-card request with secrecy and time pressure, a common fraud pattern (section 6).
  - Authentication passes but only for the free-mail provider, so passing checks do not prove legitimacy (section 2).
- MITRE ATT&CK mapping: T1566 (Phishing) for delivery, with fraud as the objective.

## 8. Recommended response for this email
- Block `karen.whitfield.ceo@freemail-provider[.]example` and `k.whitfield.private@secure-inbox[.]example`.
- Add a banner for external senders, and an alert when an internal executive's display name arrives from an external address.
- Search mailboxes for the subject "Quick favor - confidential" and purge matches.
- Confirm no one bought or sent gift cards. If they did, contact the card issuer immediately and report to finance and security.
- Train finance staff to verify unusual requests by calling the executive on a known number.
