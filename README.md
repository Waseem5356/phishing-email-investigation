# Phishing Email Investigation

This is my first hands-on cybersecurity project. I studied 7 phishing-style emails the way a SOC (security operations center) analyst would. For each email I checked who really sent it, looked at the links and attachments without opening them, wrote down the indicators (things a security team can block), and gave a verdict with a severity and a confidence level.

I am an MS MIS student at the University of Memphis. I built this to practice the real steps of an email investigation and to show my work in a way anyone can follow.

## About the data
- **S01 to S05 are synthetic (made-up) practice emails.** They use reserved `.example` domains and documentation IP addresses, so no real company or person is involved. Because the domains are fake, I could not look them up online.
- **R01 and R02 are real phishing emails** from the public [phishing_pot](https://github.com/rf-peixoto/phishing_pot) collection (`email/sample-10.eml` and `email/sample-10025.eml`). I never clicked any link or opened any attachment. I only read the emails as plain text in a code editor.

## Results at a glance
- 7 emails analyzed: 6 malicious and 1 legitimate (S05).
- Types of attack found: credential harvesting, a malicious attachment, CEO-impersonation fraud (BEC), a parcel-fee scam, a reply-based phishing email (R01) and a prize-game link lure (R02).
- 39 indicators of compromise (IOCs) saved in `iocs.csv`: 13 domains, 11 email addresses, 7 IP addresses, 6 URLs, 1 file hash and 1 file name.
- Most common sign: the sender's domain did not match the brand it claimed, and email authentication (SPF, DKIM, DMARC) failed or was missing.
- Biggest lesson: passing authentication does not make an email safe (S03), and an urgent-sounding email is not always phishing (S05).

## What I found in each sample
| Sample | What it is | Main things I noticed | Verdict |
|---|---|---|---|
| S01 (synthetic) | Fake "Microsoft Account Team" password-expiry email | Domain `micros0ft` uses a zero instead of the letter "o". From, Return-Path and Reply-To are three unrelated domains. The link text shows a Microsoft address but the real link goes elsewhere. DMARC fails. | Credential harvesting, high severity |
| S02 (synthetic) | Overdue-invoice email with an attachment | Lookalike domain with the digit "1" in place of "l". The "PDF" attachment is really an HTML file with a double extension. SPF, DKIM and DMARC all fail. | Malicious attachment lure, high severity |
| S03 (synthetic) | "CEO" asking for gift cards | Sent from a free-mail address, with a different Reply-To. It passes SPF, DKIM and DMARC, but only for the free-mail provider, not for the company. Secrecy and urgency are the fraud pattern. | Business email compromise, high severity |
| S04 (synthetic) | Fake parcel-delivery fee notice | No link to any real carrier, a shortened link that hides the destination, and a small fee with a 24-hour deadline. SPF softfail, no DKIM, no DMARC. | Payment and data harvesting, medium-high severity |
| S05 (synthetic) | Internal IT password reminder | Everything passes and aligns, DMARC is `p=reject`, the message only went through internal servers, and the link stays on the company domain. The word "URGENT" alone was not enough to call it phishing. | Legitimate, low severity |
| R01 (real) | Fake "Microsoft account team" sign-in alert | Three unrelated domains in From, Return-Path and Reply-To. Every link is a reply to one Gmail address instead of a login page, and a hidden tracking pixel comes from a third domain. DMARC returned a permanent error. | Reply-based phishing, medium severity |
| R02 (real) | Dutch "Landal Gastenpanel" prize-game email | The From domain is written with Unicode lookalike letters. Four different names appear across From, Sender, Return-Path and Reply-To. All links, even the unsubscribe link, go to one unrelated domain, with a hidden tracking pixel. SPF, DKIM and DMARC are all "none". | Brand-impersonation prize lure, medium severity |

## How I did each investigation
For every email I followed the same steps, written down in its worksheet in `analysis/`:
1. **Summary:** one short paragraph of what the email says and what it wants.
2. **Header analysis:** From, Return-Path, Reply-To, SPF, DKIM, DMARC, the first outside server in the Received chain, and whether the domains match.
3. **Sender and domain:** is it a lookalike, a typo of a real brand, or a brand-themed name? For real samples, I looked up registration data.
4. **Links:** compare the text people see with the real destination, without visiting it.
5. **Attachments:** file name, extension tricks and a SHA-256 hash.
6. **Content cues:** urgency, threats, what the email asks for, and who it pretends to be.
7. **Verdict:** a classification with severity and confidence, the evidence, and a MITRE ATT&CK technique.
8. **Recommended response:** what to block, search for and report.

## Words I learned (short glossary)
- **SPF:** a list of servers allowed to send mail for a domain.
- **DKIM:** a digital signature that shows a message was not changed and came from a domain.
- **DMARC:** tells receivers what to do when SPF and DKIM do not line up with the From address.
- **Return-Path / Reply-To:** where bounces go and where replies go. Attackers often make these differ from From.
- **Lookalike domain:** a domain that looks like a real one, for example `micros0ft` or a Unicode lookalike.
- **IOC:** an indicator of compromise, such as a bad domain, IP address or file hash.
- **Defanging:** writing `hxxp://example[.]com` so a link cannot be clicked by accident.
- **Tracking pixel:** a hidden 1x1 image that tells the sender the email was opened.
- **BEC:** business email compromise, where an attacker pretends to be an executive or vendor.

## What is in this repository
```
samples/            the raw .eml files (synthetic S01-S05, real R01-R02)
analysis/           one analysis worksheet per sample
tools/              header_parser.py, a small read-only helper script
iocs.csv            all indicators, defanged
incident-report.md  the final report with findings and recommendations
```
Start with `incident-report.md` for the summary, then open any file in `analysis/` to see how I reached each verdict.

## Tools I used
- Visual Studio Code, to read the emails and write the analysis
- ICANN registration data lookup, to check whether a domain is registered

I did **not** use VirusTotal, AbuseIPDB or URL scanners on the real samples' indicators, and I deliberately never visited the links. This is listed as a limitation in the report.

## How to run the helper script
```
python3 tools/header_parser.py samples/synthetic-01-credential-harvest.eml
```
It only reads the file and prints the main headers. It does not open links or attachments.

## Safety
Never click links or open attachments from these files. All URLs and domains in the analysis are defanged. If you want to open an `.eml` file, use a plain text editor, not an email app or a browser.

## Limitations
- This is a learning project with only 7 samples, so the results are examples, not statistics.
- Synthetic samples use fake domains, so there is no real reputation data for them.
- For the real samples, I did not check reputation services, and I never visited the links, so I cannot say what the pages behind them do.

## Author
Waseem Akram Shaik | MS in Management Information Systems, University of Memphis
