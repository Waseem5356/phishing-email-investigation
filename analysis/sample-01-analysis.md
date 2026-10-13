# Analysis: synthetic-01-credential-harvest.eml

Analyst: Waseem Akram Shaik | Date analyzed: 2026-10-10 | Sample type: synthetic

## 1. Summary
This email pretends to come from the "Microsoft Account Team" and claims the recipient's password expires in 24 hours. It pressures the recipient to click a link to "verify" the account. The link text shows a Microsoft address, but the real target is a lookalike sign-in page on `micros0ft-support[.]example`. The sender, return path and reply-to use three different unrelated domains, and DMARC fails. Verdict: credential-harvesting phishing, high severity, high confidence.

## 2. Header analysis
| Field | Value | Observation |
|---|---|---|
| From (display name + address) | "Microsoft Account Team" <no-reply@micros0ft-support[.]example> | Display name uses a trusted brand, but the domain is not Microsoft's. The 7th character of "micros0ft" is the digit zero, not the letter "o". |
| Return-Path | bounce@verify-mailer[.]example | Different domain from From. Bounces go to a bulk-mailer domain, not to Microsoft. |
| Reply-To | helpdesk.recovery@securemail-center[.]example | A third unrelated domain. Replies would go to the attacker, not to the From address. |
| SPF result | pass (smtp.mailfrom=verify-mailer[.]example) | SPF passed only for the attacker's own Return-Path domain, so it says nothing about the From address. |
| DKIM result | none | The message is not signed. A real Microsoft message would carry a DKIM signature aligned with a Microsoft domain. |
| DMARC result | fail (p=none) | Neither SPF nor DKIM aligns with the From domain. The policy is p=none, so the gateway only flags it and does not block. |
| Originating IP (bottom Received hop) | 198.51.100.77 | Client that submitted the message to smtp-out[.]verify-mailer[.]example. Relayed onward from 203.0.113.45. |
| Do From / Return-Path / Reply-To domains match? | No. Three different domains | `micros0ft-support[.]example`, `verify-mailer[.]example`, `securemail-center[.]example`. A legitimate sender normally uses one organization's domains consistently. |

Received chain notes (oldest hop first):
1. 13:14:22 UTC: message accepted from client 198.51.100.77 by `smtp-out[.]verify-mailer[.]example` using ESMTPA, which means the sender authenticated to that mail server.
2. 13:14:29 UTC: `smtp-out[.]verify-mailer[.]example` (203.0.113.45) relayed the message to the recipient organization's gateway `mail-gw[.]contoso-logistics[.]example`.
3. 13:14:31 UTC: the gateway (private address 10.20.0.5) delivered it to the internal mailbox server `mbx01`. Total transit time was about 9 seconds, consistent with an automated bulk send.

## 3. Sender and domain
- Domain(s) examined (defanged): `micros0ft-support[.]example`, `verify-mailer[.]example`, `securemail-center[.]example`
- Lookalike or typo-squat? Yes. `micros0ft` replaces the letter "o" (7th character) with the digit "0", which is easy to miss at a glance. The `-support` suffix is not a domain pattern Microsoft uses for account notices, and the other two domains have no connection to Microsoft at all.
- WHOIS / registration date (real samples only): N/A. `.example` is a reserved top-level domain (RFC 2606), so it cannot be registered or looked up.
- IP reputation (real samples only): N/A. 198.51.100.77 and 203.0.113.45 belong to documentation ranges (RFC 5737, TEST-NET-2 and TEST-NET-3), so no live reputation data exists. Enrichment is done on the real samples.

## 4. Links
| Display text | Real target (defanged) | Match? | Scan result |
|---|---|---|---|
| hxxps://account[.]microsoft[.]com/security | hxxps://login[.]micros0ft-support[.]example/signin?session=8f3a1c&redirect=owa | No | N/A (synthetic) |

Note: the plain-text part of the email shows only the Microsoft address, while the HTML part links to the lookalike domain. The `session` and `redirect=owa` parameters suggest a page built to mimic an Outlook Web sign-in.

## 5. Attachments
| File name | Type / extension trick? | SHA-256 | Lookup result |
|---|---|---|---|
| None | N/A | N/A | N/A |

## 6. Content and social-engineering cues
- Urgency / threat: "password will expire in 24 hours"; "account will be suspended"; "your data may be lost".
- Request (credentials, payment, gift cards, click, open file): click a link to "verify" the account, which leads to a sign-in form that would capture credentials.
- Greeting / tone / grammar: no personalization (no recipient name). Tone is formal and generic, and the grammar is clean, so poor grammar is not a reliable signal here.
- Impersonated entity: Microsoft (account security).

## 7. Verdict
- Classification: credential harvesting
- Severity: high   Confidence: high
- Evidence supporting the verdict:
  - DMARC fails and the From, Return-Path and Reply-To domains are three unrelated domains (section 2).
  - The visible link text points to Microsoft, but the real target is a lookalike domain using a zero for the letter "o" (sections 3 and 4).
  - Urgency and a threat of account suspension push the reader to act without checking (section 6).
- MITRE ATT&CK mapping: T1566.002, Phishing: Spearphishing Link

## 8. Recommended response for this email
- Block the sender domain `micros0ft-support[.]example`, the return-path domain `verify-mailer[.]example`, and the reply-to domain `securemail-center[.]example` at the mail gateway.
- Block the URL `hxxps://login[.]micros0ft-support[.]example/signin` at the web proxy or DNS filter.
- Search all mailboxes for the subject "Action Required: Your password expires in 24 hours" and purge matching messages.
- If any user clicked or entered credentials: reset the password, revoke active sessions and tokens, and review sign-in logs for unfamiliar locations.
- Add the indicators to the blocklist or SIEM watchlist, and tell users how to report similar messages.
