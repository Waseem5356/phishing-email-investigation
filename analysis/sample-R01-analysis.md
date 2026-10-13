# Analysis: real-R01-reply-lure-sample10.eml

Analyst: Waseem Akram Shaik | Date analyzed: 2026-10-12 | Sample type: real (public phishing_pot collection, `email/sample-10.eml`; message dated 8 Sep 2023)

## 1. Summary
A fake "Microsoft account team" email warns of unusual sign-in activity and pushes the reader to "report the user" through links that all point to a Gmail address, rather than to a login page. The sender, return path and reply-to use three unrelated domains, there is no SPF or DKIM, and DMARC returned a permanent error. A hidden image from a third domain appears to track whether the message was opened. Verdict: reply-based phishing impersonating Microsoft, medium severity, high confidence that it is malicious.

## 2. Header analysis
| Field | Value | Observation |
|---|---|---|
| From (display name + address) | "Microsoft account team ,_" <no-reply@access-accsecurity[.]com> | Not a Microsoft domain. The display name is also malformed, with a stray `,_` after "team". |
| Return-Path | bounce@thcultarfdes[.]co[.]uk | A different domain from From. Bounces would go to the sending infrastructure, not to Microsoft. |
| Reply-To | sotrecognizd@gmail[.]com | A free Gmail address. A genuine Microsoft security notice would not ask you to reply to one. |
| SPF result | none (sender IP 89.144.44.2, smtp.mailfrom=thcultarfdes[.]co[.]uk) | The domain `thcultarfdes[.]co[.]uk` publishes no SPF record that designates this IP. Nothing vouches for the sender. |
| DKIM result | none (message not signed) | No signature, so no proof of origin or integrity. |
| DMARC result | permerror, action=none (header.from=access-accsecurity[.]com) | A permanent error occurred while evaluating DMARC for the From domain. The cause was not determined: the domain is no longer registered, so its DMARC record cannot be retrieved now. |
| Originating IP (bottom Received hop) | 89.144.44.2 | The external server `thcultarfdes[.]co[.]uk` that handed the message to Microsoft's filtering. Every later hop is inside Microsoft's own network. |
| Do From / Return-Path / Reply-To domains match? | No. Three different domains | `access-accsecurity[.]com`, `thcultarfdes[.]co[.]uk`, `gmail[.]com`. A legitimate sender normally uses one organization's domains consistently. |

Additional header observations:
- `X-Priority: 1` and `Importance: high` add artificial urgency.
- Two `Content-Length` headers with different, very large values appear. This is unusual; note it without drawing a conclusion.
- `X-MS-Exchange-Organization-AuthAs: Anonymous` is consistent with a message from outside the organization.
- `X-MS-Exchange-Organization-SCL: 5` is Microsoft's spam confidence score. Microsoft's documentation (learn.microsoft.com, "Spam confidence level (SCL) in EOP") says SCL 5 or higher historically meant a message was considered bad, but that in cloud organizations the SCL value alone does not decide the spam verdict or the action taken. So it is a supporting signal here, not proof.
- `To: phishing@pot` is the collection's anonymized placeholder, not a real recipient.

Received chain notes (oldest hop first):
1. 05:47:04 UTC, 8 Sep 2023: `thcultarfdes[.]co[.]uk` (89.144.44.2) connected to Microsoft's inbound protection frontend `DB8EUR06FT032.mail.protection.outlook.com`. This is the only external hop.
2. 05:47:04 UTC: the Microsoft protection server passed the message to `DB8P191CA0014.outlook.office365.com` over Frontend Transport.
3. 05:47:04 UTC: it moved on to `SJ0PR19MB6679.namprd19.prod.outlook.com` using Microsoft SMTP with TLS 1.2.
4. 05:47:06 UTC: final delivery to the mailbox server `MN0PR19MB6312.namprd19.prod.outlook.com` over HTTPS. End-to-end latency was about 2 seconds (`X-MS-Exchange-Transport-EndToEndLatency`).

Why the chain is mostly Microsoft servers: the recipient mailbox sat in Microsoft 365, so the hops after the first are the recipient's own provider. They are not the attacker's infrastructure.

## 3. Sender and domain
- Domain(s) examined (defanged): `access-accsecurity[.]com`, `thcultarfdes[.]co[.]uk`, `gmail[.]com` (Reply-To), `thebandalisty[.]com` (tracking pixel, see section 4)
- Lookalike or typo-squat? `access-accsecurity[.]com` is not a Microsoft domain. It blends the words "access" and "security" to sound official, and the "accsecurity" spelling is a truncated form, which is a common brand-theme technique. It is not a one-character swap of a real Microsoft domain, so call it "brand-themed, not a direct typo-squat." `thcultarfdes[.]co[.]uk` looks like random letters, which suggests throwaway sending infrastructure.
- WHOIS / registration date: ICANN lookup for `access-accsecurity[.]com` on 2026-10-12 returned "The requested domain was not found in the Registry or Registrar's RDAP server," so it is no longer registered and no registrar or creation date is available. The email is from September 2023, so it has likely expired since. `thcultarfdes[.]co[.]uk`: registration data was not checked in this analysis.
- SPF and DMARC records: current DNS records for the two sending domains were not checked. The authentication results recorded in the email headers (section 2) are used instead, since they show what Microsoft saw at delivery in 2023.
- IP ownership (89.144.44.2): the RIPE registry (RDAP, queried 2026-10-12) lists network name MSCODE, country PL (Poland), range 89.144.44.0/24, registrant MSCode, abuse contact GHOSTnet GmbH. Registry data shows who holds the range, not that the sender is malicious. IP reputation (AbuseIPDB, VirusTotal) was not checked in this analysis.

## 4. Links
| Display text | Real target (defanged) | Match? | Scan result |
|---|---|---|---|
| Link on the recipient line in the sign-in paragraph | mailto:sotrecognizd@gmail[.]com (cc to the same address, subject "Report The User") | N/A (reply link, not a web page) | N/A |
| "Report The User" button | mailto:sotrecognizd@gmail[.]com (cc to the same address, subject "unusual signin activity", body "Report The User") | N/A | N/A |
| "click here" opt-out | mailto:sotrecognizd@gmail[.]com (cc to the same address, subject "Unsubscribe me") | N/A | N/A |
| Hidden 1-pixel image (likely tracking pixel; width and height 1px, visibility:hidden) | hxxp://thebandalisty[.]com/track/o43062rdzGz18708448Gdrw1821750fYo33632dSjh176 | N/A | Not scanned. The URL was deliberately not visited or submitted to a live scanner, because loading it would tell the sender the email was opened. |

Observation: every clickable element sends mail to the same Gmail address instead of opening a sign-in page. There is no credential-harvesting website in this sample.

## 5. Attachments
| File name | Type / extension trick? | SHA-256 | Lookup result |
|---|---|---|---|
| None | N/A | N/A | N/A |

## 6. Content and social-engineering cues
- Urgency / threat: a fake "unusual sign-in activity" alert. The body claims "A user from Russia/Moscow just logged into your account from a new device" and lists an IP address (103.225.77.255), a standard scare tactic. That IP is lure content, not attacker infrastructure, so it is not recorded as an indicator. `Importance: high` reinforces it.
- Request (credentials, payment, gift cards, click, open file): contact the Gmail address to "report the user." The reader is invited to reply, which would confirm the mailbox is live and open a conversation with the sender.
- Greeting / tone / grammar: generic, no personal name. The malformed display name is a quality signal.
- Impersonated entity: Microsoft account team.

## 7. Verdict
- Classification: reply-based phishing with a likely tracking pixel
- Severity: medium   Confidence: high that it is malicious; medium on the exact end goal (the follow-up exchange is not visible in this sample)
- Evidence supporting the verdict:
  - Microsoft is impersonated from `access-accsecurity[.]com`, with three unrelated domains across From, Return-Path and Reply-To (section 2).
  - No SPF, no DKIM and a DMARC permerror, so nothing authenticates the sender (section 2).
  - Every link goes to a Gmail address, and a hidden image from a separate domain appears to track opens (section 4).
- MITRE ATT&CK mapping: T1566 (Phishing), parent technique only. MITRE's sub-techniques are T1566.001 attachment, .002 link, .003 via service and .004 voice. This email has no attachment and no web link (every link is a mailto), so none of them clearly fits, and the parent technique is used.

## 8. Recommended response for this email
- Limitation of this analysis: reputation and registration checks for `thcultarfdes[.]co[.]uk`, both IPs and the tracking URL were not performed, and the follow-up exchange after a reply is not visible in this sample.
- Block the sender domain `access-accsecurity[.]com`, the return-path domain `thcultarfdes[.]co[.]uk` and the tracking domain `thebandalisty[.]com` at the mail gateway and DNS filter.
- Block `sotrecognizd@gmail[.]com` as a sender and flag any outbound mail to it.
- Block or alert on the sending IP 89.144.44.2.
- Search all mailboxes for the subject "Microsoft account unusual signin activity" and purge matches.
- If any user replied or clicked: tell them not to engage further, reset their password if any credentials or codes were shared, revoke sessions and review sign-in logs.
- Report the Gmail address to Google through its abuse reporting process.
- Remind users that Microsoft security alerts do not ask you to email a Gmail address, and that account activity should be checked by going to the account page directly.
