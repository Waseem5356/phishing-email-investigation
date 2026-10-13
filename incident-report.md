# Phishing Investigation: Incident Report

**Analyst:** Waseem Akram Shaik
**Report date:** 2026-10-12
**Scope:** 7 email samples (5 synthetic training samples, 2 real public samples)
**Status:** Complete

> Samples labeled "synthetic" were created as training data using reserved example domains and documentation IP ranges. They are not real incidents. Samples labeled "real" come from a public research collection (phishing_pot) and were analyzed without opening links or attachments.

## 1. Executive summary
I analyzed 7 emails: 5 synthetic (S01 to S05) and 2 real (R01 and R02). Six were malicious and one (S05) was a legitimate internal notice, which I included to practice not over-flagging urgent-sounding mail. The malicious samples used credential harvesting, a malicious attachment, CEO-impersonation fraud, a parcel-fee scam, a reply-based lure (R01) and a prize-game link lure (R02). Almost every malicious sample failed or lacked email authentication and used a sender domain that did not match the brand it claimed, and the exception (S03) passed authentication only because it was sent from a free-mail provider. The top recommendation is to enforce DMARC on owned domains and add gateway rules for lookalike sender domains, external-sender banners and display-name impersonation.

## 2. Method
- Collected full raw headers and bodies (.eml) for each sample and opened them only as text in a code editor, never in a mail client or browser.
- Reviewed authentication results (SPF, DKIM, DMARC), sender and reply-to alignment, and the Received chain.
- Inspected link targets and attachment metadata without opening them; recorded the SHA-256 hash of the one attachment (S02).
- Extracted indicators of compromise (IOCs) and defanged all of them (for example `hxxp` and `[.]`).
- For the real samples, enriched indicators with registry data (domain registration for `access-accsecurity.com` and `byunmedia.com`, IP ownership for both sending IPs) and the real brand's DMARC policy. Reputation services (AbuseIPDB, VirusTotal) and live URL scanning were not used; the links were deliberately never visited.
- Classified each sample and rated severity and confidence separately.

Tools used: Visual Studio Code and the ICANN registration data lookup.

## 3. Findings summary
| Sample | Type | SPF / DKIM / DMARC | Key evidence | Verdict | Severity | Confidence |
|---|---|---|---|---|---|---|
| S01 | Synthetic | pass (attacker's own domain only) / none / fail | Lookalike `micros0ft` domain (zero for "o"), three unrelated domains in From, Return-Path and Reply-To, link text does not match target | Credential harvesting | High | High |
| S02 | Synthetic | softfail / fail / fail | Lookalike domain with digit "1" for "l", double-extension HTML attachment disguised as a PDF, overdue and collections threat | Malicious attachment lure | High | High |
| S03 | Synthetic | pass / pass / pass | Executive title sent from a free-mail address, different Reply-To domain, secret gift-card request. Authentication passes for the provider only | BEC (CEO impersonation) | High | Medium-high |
| S04 | Synthetic | softfail / none / none | Brand-less tracking domain, shortened link hiding the destination, fee with 24-hour deadline | Payment and data harvesting | Medium-high | Medium-high |
| S05 | Synthetic | pass / pass / pass | Internal-only relay path, same-domain link, DMARC `p=reject`. "URGENT" wording alone is not evidence | Legitimate | Low | Medium-high |
| R01 | Real | none / none / permerror | Fake Microsoft account alert, three unrelated domains, Reply-To and every link go to one Gmail address, hidden tracking pixel from a third domain | Reply-based phishing | Medium | High |
| R02 | Real | none / none / none | Dutch "Landal" prize game, Unicode lookalike From domain, four unrelated names across From, Sender, Return-Path and Reply-To, all links including unsubscribe go to `byunmedia.com`, hidden tracking pixel, Microsoft SCL 9 and Junk delivery | Brand-impersonation prize lure (link-based) | Medium | High that it is malicious, medium on the end goal |

## 4. Indicators of compromise
See `iocs.csv`. Total indicators: 39 (domains 13, email addresses 11, IPs 7, URLs 6, file hashes 1, file names 1). By sample: S01 8, S02 5, S03 4, S04 3, S05 0 (legitimate, so nothing was recorded), R01 8, R02 11. By confidence: high 20, medium 18, low 1.

Impersonated brands (for example `landal[.]nl` and Microsoft) and shared services (Gmail, Microsoft's own mail servers) are not recorded as attacker indicators, because blocking them would cause false positives.

## 5. Incident response mapping (NIST)
**Detection and analysis:** Each message was identified by combining several signals rather than one. The strongest were domain mismatch across From, Return-Path and Reply-To, DMARC results, lookalike or Unicode-lookalike domains, and link or attachment tricks (S01 to S04, R02). R01 was caught by its mismatched domains and the fact that every link was a reply to a free-mail address. S03 shows that passing authentication is not enough, and S05 shows that urgency alone is not enough.

**Containment, eradication and recovery** (recommended):
- Block sender addresses and domains at the mail gateway.
- Block malicious URLs and IPs at the proxy and firewall.
- Do not blindly block domains that may belong to an unrelated organization (for example `civilsocietyroundtable[.]co[.]il` in R02); block by message pattern and consider notifying the owner.
- Search for and purge matching messages from all mailboxes.
- For any user who clicked, replied or entered credentials: reset the password, revoke sessions, review sign-in logs.
- For any opened attachment: isolate the endpoint and run an EDR scan.

**Post-incident activity:**
- Report the phishing domains to the registrar and hosting provider, and report the impersonated brand's abuse contact.
- Feed the IOCs to the SIEM or blocklist.

## 6. Prevention recommendations
1. Enforce DMARC at p=quarantine or p=reject for owned domains. The real brand in R02 publishes `p=reject`, which pushed that attacker to a lookalike domain instead.
2. Warn on external senders and display-name impersonation.
3. Add a gateway rule that flags sender domains containing non-ASCII lookalike characters.
4. Enable link rewriting and attachment sandboxing, and strip HTML attachments with double extensions.
5. Add a one-click "Report phish" button and run regular awareness training.
6. Require out-of-band verification for payment and gift-card requests.

## 7. Lessons learned
- SPF or DKIM passing does not mean an email is legitimate. In S03 and S01, authentication passed for the attacker's own or a free-mail domain, and what mattered was whether it aligned with the visible From domain.
- Even the unsubscribe link and the "report" link can be part of the attack. In R01 every link was a reply to the attacker, and in R02 the unsubscribe link pointed to the same unrelated domain as the play button.
- Headers can hide in plain sight. In R02 the Unicode lookalike domain only showed up after decoding an encoded header, so reading raw headers matters.
- A legitimate email can look urgent (S05), so urgency is a reason to verify, not proof of phishing.
- Not every domain in a phishing email is attacker-owned. Impersonated brands and possibly abused unrelated domains need different handling from throwaway attacker domains.

## 8. Limitations
- Synthetic samples use reserved domains and IPs, so no live reputation data exists for them.
- Real samples are from 2023 and 2026, and registration and DNS data was checked in October 2026, so one domain (`access-accsecurity[.]com`) had since expired and its records could not be retrieved.
- Reputation services (AbuseIPDB, VirusTotal) and URL scanning were not used, and the pages behind the links were never visited, so the end goal of R02's lure is unknown.
- Registration data for some secondary domains (`thcultarfdes[.]co[.]uk`, `gasten-landal[.]nl`, `civilsocietyroundtable[.]co[.]il`) was not checked.
- Small sample size (7 emails); results are illustrative, not statistical.
