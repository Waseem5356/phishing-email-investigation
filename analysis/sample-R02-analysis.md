# Analysis: real-R02-landal-prize-game.eml

Analyst: Waseem Akram Shaik | Date analyzed: 2026-10-12 | Sample type: real (message dated 8 Jul 2026; public phishing_pot collection, `email/sample-10025.eml`)

## 1. Summary
A Dutch-language email posing as the "Landal Gastenpanel" (Landal GreenParks holiday parks) invites the reader to play a "memory game" to win free stays. The visible sender address uses Unicode look-alike letters in its domain, the Sender and Reply-To headers use two other Landal-themed names, and the Return-Path belongs to an unrelated Israeli domain. Nothing authenticates (SPF, DKIM and DMARC are all none), and Microsoft rated it SCL 9 and delivered it to Junk. The play button, the unsubscribe link and a hidden 1-pixel image all point to the unrelated domain `byunmedia[.]com`. Verdict: brand-impersonation prize-lure phishing, medium severity, high confidence that it is malicious. The page behind the links was not examined.

## 2. Header analysis
| Field | Value | Observation |
|---|---|---|
| From (display name + address) | "Landal Gastenpanel" <Landal-Gastenpanel@𝗹𝗮𝗻𝗱𝗮𝗹-client-48106818.𝗻𝗹> | The domain is written with Unicode mathematical bold letters, which look like "landal-client-48106818.nl" but are different characters (a homoglyph trick). The number looks machine-generated. |
| Sender | "Landal Gastenpanel" <noreply@landal[.]nl> | A different address from From, using the real brand's domain. Anyone can write any value in this header, and nothing authenticates it. |
| Return-Path | info@civilsocietyroundtable[.]co[.]il | An unrelated organization's domain. Why it is used is not stated: it could be registered by the attacker or abused. Do not assume which. |
| Reply-To | no-reply@gasten-landal[.]nl | A brand-themed lookalike, and an odd choice, since a "no-reply" address cannot receive your reply. |
| SPF result | none (sender IP 5.196.201.3, smtp.mailfrom=civilsocietyroundtable[.]co[.]il) | That domain does not designate this IP as an authorized sender. |
| DKIM result | none (message not signed) | No signature. |
| DMARC result | none, action=none (header.from is the Unicode lookalike domain) | The From domain has no DMARC policy, so nothing tells receivers what to do with spoofed mail. |
| Originating IP (bottom Received hop) | 5.196.201.3 | First external server. Its reverse-DNS name is `ip3.ip-5-196-201[.]eu`, which looks like an auto-generated hosting name. Check who owns the address before saying more. |
| Do From / Sender / Return-Path / Reply-To domains match? | No. Four different names | Unicode lookalike (From), `landal[.]nl` (Sender), `civilsocietyroundtable[.]co[.]il` (Return-Path), `gasten-landal[.]nl` (Reply-To). |

Additional header observations:
- **Encoded header.** The `Authentication-Results` and `X-SID-PRA` lines appear as `=?utf-8?B?...?=` text. This is MIME encoding (Base64), used because the header contains non-ASCII characters. Decoding it (CyberChef, "From Base64") reveals the Unicode lookalike domain.
- **Clock gap.** The `Date` header says 01:52:41 UTC, but Microsoft first saw the message at 05:52:50 UTC, about four hours later. This may be a sender clock or time-zone error. Note it without a conclusion.
- **Microsoft's verdict.** `X-MS-Exchange-Organization-SCL: 9` and delivery marked as Junk (`RF:JunkEmail`). Microsoft's documentation says SCL values can be mapped to "high confidence spam" by mail flow rules, but that the SCL value alone does not decide the verdict or action. Here the Junk delivery is the recorded outcome.
- `X-MS-Exchange-Organization-AuthAs: Anonymous` is consistent with an outside sender.
- `To` and `CC` are the collection's anonymized `phishing@pot` placeholder.

Received chain notes (oldest hop first):
1. 05:52:50 UTC, 8 Jul 2026: `ip3.ip-5-196-201[.]eu` (5.196.201.3) connected to Microsoft's inbound protection frontend `DB5PEPF00014B9E.mail.protection.outlook.com`. This is the only external hop.
2. 05:52:50 UTC: Microsoft's protection server handed it to `DUZPR01CA0182.outlook.office365.com` over TLS 1.3.
3. 05:52:51 UTC: it moved to `PH0PR10MB5731.namprd10.prod.outlook.com` over TLS 1.2.
4. 05:52:53 UTC: final delivery to `MW4PR10MB5749.namprd10.prod.outlook.com` over HTTPS. End-to-end latency was about 3.3 seconds.

Hops 2 to 4 are Microsoft's own servers (the recipient's provider), not attacker infrastructure.

## 3. Sender and domain
- Domain(s) examined (defanged): `𝗹𝗮𝗻𝗱𝗮𝗹-client-48106818[.]𝗻𝗹` (From), `gasten-landal[.]nl` (Reply-To), `civilsocietyroundtable[.]co[.]il` (Return-Path), `byunmedia[.]com` (all links). The impersonated brand is `landal[.]nl`, which is not attacker infrastructure.
- Lookalike or typo-squat? Yes, in two ways. The From domain is a **homoglyph** domain: letters from the Unicode "mathematical bold" block that look like ASCII letters. `gasten-landal[.]nl` is **brand-themed**, since it combines the Dutch word for "guests" with the brand name.
- WHOIS / registration date: `byunmedia[.]com` (Verisign RDAP, queried 2026-10-12): registrar NameCheap, Inc., created 2024-07-17, expires 2027-07-17, last changed 2026-10-05, status client transfer prohibited. It is registered and was changed days before this analysis; that alone does not prove malicious use. Registration data for `gasten-landal[.]nl` and `civilsocietyroundtable[.]co[.]il` was not checked in this analysis.
- SPF and DMARC records: current DNS records for the attacker-side domains were not checked; the results recorded in the headers (section 2) are used instead. The real brand `landal[.]nl` publishes a strict DMARC policy (DNS query for `_dmarc.landal.nl` on 2026-10-12: `p=reject`, `aspf=s`, `adkim=s`), so spoofing its exact domain is blocked by receivers that enforce DMARC. That is a plausible reason the sender used a different lookalike domain in From, but the email does not state the motive.
- IP ownership (5.196.201.3): RIPE RDAP (queried 2026-10-12) lists network name OVH_451668059, country ES (Spain), range 5.196.201.0/30 (a 4-address block), registrant a private individual's handle, with OVH as maintainer and technical contact. This looks like a small block assigned out of OVH hosting. IP reputation (AbuseIPDB, VirusTotal) was not checked in this analysis.

## 4. Links
| Display text | Real target (defanged) | Match? | Scan result |
|---|---|---|---|
| "Speel nu mee en win" (button) | hxxp://byunmedia[.]com/4qpLVK4606sjfV180yoiitqxrfw19ICEMJOSFXLTTDDL127587NUCI1137u1 | No. The text implies Landal, but the domain is unrelated. | Not scanned. The URL was not visited. |
| "Klik hier om u af te melden" (unsubscribe) | hxxp://byunmedia[.]com/5gnXnN4606EykK180unrmvebqex19HKSLRUYGWJIPUJP127587IKRB1137l1 | No. It goes to the same unrelated domain. | Not scanned. The URL was not visited. |
| Hidden 1x1 image (`display:none`) | hxxp://byunmedia[.]com/track/3GhfIJ4606qxzh180ijaiigteok19DWZPSAERQPXIJZT127587KKUE1137K1 | N/A (hidden image) | Not scanned. The image was not loaded, since loading it would confirm the message was opened. |

Observations: all three links use plain `http`, not `https`. The long strings look like per-recipient tokens. Even the unsubscribe link goes to the same domain, so clicking it would confirm the address is live. Do not visit any of them or submit them to urlscan.io.

## 5. Attachments
| File name | Type / extension trick? | SHA-256 | Lookup result |
|---|---|---|---|
| None | N/A | N/A | N/A |

## 6. Content and social-engineering cues
- Urgency / threat: low pressure. The lure is a prize ("win a memorable stay") rather than a threat. It stresses "completely free and without obligation" to lower the reader's guard.
- Request (credentials, payment, gift cards, click, open file): click the button to play an online game. What the page asks for next is unknown.
- Greeting / tone / grammar: no personal name. The Dutch is fluent and the layout looks professional.
- Impersonated entity: Landal GreenParks. The footer copies a company name and an Amsterdam street address to look credible. Do not confirm that address from this email.

## 7. Verdict
- Classification: brand-impersonation prize-lure phishing (link-based)
- Severity: medium   Confidence: high that it is malicious; medium on the end goal, because the destination was not examined
- Evidence supporting the verdict:
  - Four unrelated names across From, Sender, Return-Path and Reply-To, including a Unicode lookalike domain (section 2).
  - No SPF, DKIM or DMARC, and Microsoft scored it SCL 9 and sent it to Junk (section 2).
  - Every link, including the unsubscribe link, points to one unrelated domain, with a hidden tracking image from the same domain (section 4).
- MITRE ATT&CK mapping: T1566.002, Phishing: Spearphishing Link (sub-technique ID and name confirmed on attack.mitre.org). The email is a mass lure and not targeted at one person, so treat "spearphishing" as MITRE's label for the link-based method.
- Limitation: the page behind the links was not examined, so we cannot say whether it collects personal data, payment details or leads to something else.

## 8. Recommended response for this email
- Limitation of this analysis: reputation checks for both IPs and the three links, and registration data for `gasten-landal[.]nl` and `civilsocietyroundtable[.]co[.]il`, were not performed.
- Block `byunmedia[.]com`, `gasten-landal[.]nl` and the lookalike From domain at the mail gateway and DNS filter, and block IP 5.196.201.3.
- Do not blindly block `civilsocietyroundtable[.]co[.]il`. It may belong to an unrelated organization. Block by matching this message pattern, and consider notifying that organization.
- Add a gateway rule that flags senders whose domain contains non-ASCII lookalike characters.
- Search all mailboxes for the subject "Uw kans op een exclusief verblijf in de natuur" and purge matches.
- Tell users not to click the play button or the unsubscribe link, and to go to the brand's official website directly.
- Report the message to the impersonated brand (Landal) so they can warn customers.
