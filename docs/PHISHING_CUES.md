# Riggs: Phishing Cues

## Overview

This is a catalog of the cues that security-awareness training tells people to
look for in a suspicious email. Each cue is traced to the document that states
it and classified by whether a Riggs mail sensor could decide it. The catalog
is the input for the phishing engine's cue functions.

Status: proposal for review, written 2026-11-12. Nothing here is implemented
and no weight is implied. A cue's weight, including its sign, comes from
measurement on real mail.

How to read it:

- Every entry cites a document that was read while writing this file.
  Section 1 says how each one was read and what could not be read.
- The **Cue** line restates the source in our own words. The **Decide** and
  **Misfire** lines are this catalog's proposals, not statements from the
  sources.
- Not every cue is a red flag. NIST defines a cue as a property that either
  pulls the reader toward clicking or alerts them to the phish (NIST p. 5).
  Legal footers, security wording, offers and a trusted-looking sender are
  things a phishing email does to look convincing, and honest mail does them
  too.
- For language cues, "computable" means decidable by matching the subject and
  body against a phrase list. Section 4 holds the only phrases the sources
  supply. The rest of each list has to come from measurement.

## 1. Sources

| Key | Document | Publisher | Date or version | What was read |
|---|---|---|---|---|
| NIST | *NIST Phish Scale User Guide*, NIST Technical Note 2276 (S. Dawkins, J. Jacobs) | National Institute of Standards and Technology | November 2023 | Whole document, 47 PDF pages, from a local copy of the PDF |
| KB4 | *Social Engineering Red Flags*, one-page infographic with 22 red flags | KnowBe4, LLC | © 2021 | Whole page, including the sample email at its center |
| KB4-blog | "Share the Red Flags of Social Engineering Infographic With Employees" (R. Grimes) | KnowBe4 blog | Published 2020-04-08 | Whole post |
| CISA-GUIDE | *Phishing Guidance: Stopping the Attack Cycle at Phase One* (CISA, NSA, FBI, MS-ISAC) | CISA | October 2023, TLP:CLEAR | Whole document, 14 pages |
| CISA-RRP | "Recognize and Report Phishing" (Secure Our World) | CISA | No date shown; marked "Archived Content" | Whole page |
| CISA-TIP | Secure Our World phishing tip sheet, "Avoid Phishing Scams with Three Simple Tips" | CISA | "As of August 14, 2023" | Both pages, from a copy on a state government site (see below) |
| CISA-ASE | "Avoiding Social Engineering and Phishing Attacks" | CISA | Released 2021-02-01; marked "Archived Content" | Whole page |
| CISA-TEA | "Teach Employees to Avoid Phishing" | CISA | No date shown; cites the FBI's 2024 Internet Crime Report; not marked archived | Whole page |
| FTC | "How To Recognize and Avoid Phishing Scams" | Federal Trade Commission, Consumer Advice | "September 2022" shown on the page | The section "How To Recognize Phishing" only, through a fetch tool (see below) |
| RFC 5322 | *Internet Message Format* | IETF | October 2008 | Section 3.6.5 only, for one decision rule |

URLs:

- NIST: <https://nvlpubs.nist.gov/nistpubs/TechnicalNotes/NIST.TN.2276.pdf>
  (DOI <https://doi.org/10.6028/NIST.TN.2276>). The local copy was supplied
  with the task and was not downloaded again.
- KB4: <https://www.knowbe4.com/hubfs/Social-Engineering-Red-Flags.pdf>
- KB4-blog: <https://blog.knowbe4.com/red-flags-social-engineering-infographic>
- CISA-GUIDE:
  <https://www.cisa.gov/sites/default/files/2023-10/Phishing%20Guidance%20-%20Stopping%20the%20Attack%20Cycle%20at%20Phase%20One_508c.pdf>
- CISA-RRP: <https://www.cisa.gov/secure-our-world/recognize-and-report-phishing>
- CISA-TIP, copy read:
  <https://www.mass.gov/files/documents/2023/10/12/Secure-Our-World-Phishing-Tip-Sheet.pdf>
- CISA-ASE:
  <https://www.cisa.gov/news-events/news/avoiding-social-engineering-and-phishing-attacks>
- CISA-TEA:
  <https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/teach-employees-avoid-phishing>
- FTC: <https://consumer.ftc.gov/articles/how-recognize-avoid-phishing-scams>
- RFC 5322: <https://www.rfc-editor.org/rfc/rfc5322.txt>

All but the NIST copy were fetched on 2026-11-12. SHA-256 of the PDF files
read:

| File | SHA-256 |
|---|---|
| NIST | `0c0e41eb3ef55e5f813a844bc515465d5ede5503c458fd0a51d9089a569b092f` |
| KB4 | `496e3f2a19e1d0984e1b7e3a56eee47474177815d92ace038949f4b368e3c30e` |
| CISA-GUIDE | `07f4a53bb3a64794f4325b4d79b43f09f2ce7f21d1fd5cf3ce0f7c5e783e81aa` |
| CISA-TIP (copy read) | `d8ded66e8484f18c9d605ab9113cd7d4be766f4799aac6ecf9dd3772cbf8bd69` |

### NIST license sentence

> "The NIST Phish Scale is free to use for academic purposes. For any
> commercial use, companies will need to reach out to our partnership office
> for a license."

NIST TN 2276, PDF page 3 of 47: the unnumbered publication-information page
between the title page and page i.

This catalog uses TN 2276 as a cited list of ideas, the meaning of its 23 cues
restated in our own words, and uses none of its scoring method: no cue
counting, no premise-alignment rating, no detection-difficulty rating. The
only NIST text carried over is the 23 cue names, listed in section 6.1 so that
coverage can be checked, and the short quoted examples in section 4.

### How citations are written

- NIST page numbers are the printed ones. The PDF page index is the printed
  number plus 7, so printed page 9 is PDF page 16.
- NIST "section 2.2.1 element n" refers to its premise-alignment elements.
  They are not among the 23 cues and are cited only as supporting context.
- CISA-GUIDE's printed page numbers equal its PDF page index.
- KB4 is one page and its bullets are not numbered in the original. "FROM 4"
  means the fourth bullet under FROM in reading order. The sections hold
  FROM 1-7, TO 1-2, HYPERLINKS 1-3, DATE 1, SUBJECT 1-2, ATTACHMENTS 1-2 and
  CONTENT 1-5, which is 22.
- Web pages are cited by heading and list position. CISA-ASE "indicator 3"
  is the third item under "What are common indicators of phishing attempts?".
  CISA-TIP "sign 3" is the third item under "Recognize the common signs".
  FTC "list item 3" is the third item of the first list under "How To
  Recognize Phishing", and "example sign 2" is the second item of the list
  that follows the page's sample email.

### What could not be read

- **CISA's own copy of the tip sheet.** The download link on CISA-RRP returns
  CISA's "Page Not Found" page (HTTP 404), and so does the large-print tip
  sheet archive linked from CISA's resources archive page. The copy read is
  hosted by a state government and dated August 14, 2023. The file CISA linked
  sat in a September 2024 upload folder, so CISA's last edition may differ
  from the one cited here.
- **FTC.** The site refused a plain download, so the page was read only
  through a fetch tool that returns the page as model-processed text. Three
  retrievals were made with different questions. Every FTC wording used here
  came back the same in each retrieval that covered it, at least two; one
  sentence that one retrieval gave and another reported absent was dropped.
  None of it has been checked against the raw page, and no entry rests on FTC
  alone.
- **The papers NIST cites for each cue** (its reference list, pp. 19-20) were
  not read. This catalog cites NIST's own text only.
- CISA marks CISA-RRP and CISA-ASE as archived content that may be out of
  date. CISA-TEA is the only CISA web page read that is not marked archived.

## 2. What a sensor can see

A cue is classified against what a webmail page or a mail add-in can hand to
the daemon. Field names are those of the planned `CheckMail` observation; if
the frozen contract renames a field, read the names here accordingly.

| Field | Content |
|---|---|
| `from_name`, `from_addr` | Sender display name and address |
| `reply_to` | Reply-to address; often not available in Gmail's page |
| `to` | Recipient addresses |
| `subject`, `body_text` | Subject, and the body as text |
| `links` | Each link as visible `text` plus target `href` |
| `attachments` | Attachment file names |

Per-user history kept by the daemon:

- **login-domain set**: the domains where this user has logged in
- **seen-sender set**: whether a sender has been seen before, by domain, or by
  address at a free mail provider

There is no access to raw headers, authentication results, rendered
appearance, images or logos. The observation also carries no send time, and
only the names of attachments, not their content.

Classification:

- `computable`: decidable from the fields above, with at most a fixed list
  (phrases, file extensions, shortener hosts, a word list)
- `needs history`: also needs one of the two histories, which the entry names
- `not computable`: needs something else, which the entry names

## 3. Catalog

### 3.1 Sender

#### `display_name_address_mismatch`

- **Cue:** The name shown for the sender points to a different identity than
  the address the mail really comes from, or than the address a reply would
  go to.
- **Sources:** NIST Table 2 (p. 9), B.2.2 (p. 30), worksheet A.1 part 1
  (p. 22); CISA-TIP p. 1, sign 5; CISA-RRP, "Omar" story.
- **Class:** `computable`: `from_name`, `from_addr`, and `reply_to` when the
  sensor can supply it.
- **Decide:** fire when the display name contains an address or domain other
  than the one in `from_addr`, or shares no word with `from_addr` (and with
  `reply_to`). **Misfire:** people whose address is a handle unrelated to
  their name, and services that send on someone's behalf.
- **Note:** the CISA sources speak of the "supposed sender", who may be
  claimed in the body or by branding, which this check does not see. No source
  read compares the From and Reply-To addresses with each other, so that is
  not proposed.

#### `domain_lookalike_misspelling`

- **Cue:** A domain in the sender address or in a link is a near-copy of a
  domain the reader knows, changed by a character or two: letters swapped,
  dropped or added, or a look-alike pair such as "rn" for "m".
- **Sources:** NIST Table 2 (p. 9), B.2.4 (p. 31), worksheet A.1 parts 1 and 2
  (pp. 22-23); KB4 FROM 4, HYPERLINKS 3; CISA-RRP "Recognize" item 4;
  CISA-ASE indicators 1 and 3; CISA-TIP p. 2 (sample sender).
- **Class:** `needs history`: login-domain set, as the list of domains that
  count as known. Fields: `from_addr`, `links[].href`, and domains written in
  `links[].text`.
- **Decide:** fire when a registrable domain is not in the login set but is
  one edit, or one look-alike substitution, away from a domain that is.
  **Misfire:** an honest domain that sits one character from a known one,
  most likely with short names.
- **Note:** NIST counts this cue only when the imitated domain is one the
  audience would recognize (B.2.4, p. 31). The login set is this catalog's
  stand-in for that.

#### `domain_lookalike_suffix_swap`

- **Cue:** A known name appears under a different top-level suffix from the
  one the reader knows.
- **Sources:** NIST B.2.4, third example (p. 31); CISA-ASE indicator 3.
- **Class:** `needs history`: login-domain set. Fields as for
  `domain_lookalike_misspelling`.
- **Decide:** fire when the name left of the public suffix equals that of a
  login-set domain and the suffix differs. **Misfire:** organizations that
  run the same name under several suffixes, such as country sites or a `.org`
  beside a `.com`.

#### `domain_lookalike_embedded`

- **Cue:** A known domain or name is carried inside a different host: as the
  leading labels of an unrelated domain, or as part of a longer invented name.
- **Sources:** KB4-blog, "Number One Most Suspicious Sign" (two of its three
  examples); KB4 FROM 4 (its example adds a word to a misspelled name).
- **Class:** `needs history`: login-domain set. Fields as for
  `domain_lookalike_misspelling`.
- **Decide:** fire when a login-set domain forms the leading labels of a host
  with a different registrable domain, or a login-set name occurs inside a
  longer label of a different registrable domain. **Misfire:** third-party
  platforms that carry a customer's name in their own host names (help desks,
  mail and survey services), and brand names that are also common words.
- **Note:** the sources give examples only. The rule is this catalog's
  reading of them.

#### `brand_name_in_freemail_sender`

- **Cue:** The sender's address is at a free mail provider and its local part
  carries the name of an organization the reader knows.
- **Sources:** KB4-blog, "Number One Most Suspicious Sign" (first example).
  NIST B.2.2 (p. 30) has a related example: a role name as display name with
  a reply-to address at a free mail provider.
- **Class:** `needs history`: login-domain set, for the names. It also uses
  the free-mail domain list the daemon already needs for sender history.
- **Decide:** fire when `from_addr` is at a free-mail domain and its local
  part contains the name of a login-set domain. **Misfire:** personal
  addresses that include an employer or product name, and short names that
  occur inside ordinary words.
- **Note:** one example in one source.

#### `sender_never_seen`

- **Cue:** The reader has no earlier mail from this sender.
- **Sources:** KB4 FROM 1, 5, 6 and 7.
- **Class:** `needs history`: seen-sender set.
- **Decide:** fire when the sender's domain (or address, at a free mail
  provider) is not in the seen-sender set. **Misfire:** every honest first
  contact, such as a new shop, a new colleague or a sign-up confirmation, and
  all mail until the set has filled.
- **Note:** "vouched for by someone I trust" (FROM 5) has nothing to observe.
  "Recently" (FROM 7) would need a last-seen time per sender.

#### `authority_role_sender_name`

- **Cue:** The sender presents as a role or department with authority over
  the reader, such as management, HR or IT, rather than as a named person.
- **Sources:** NIST B.5.6 (pp. 36-37) and Appendix B Figure 5 (p. 37), where
  the sender shown in the From line is the marked cue; NIST B.2.2 (p. 30);
  CISA-GUIDE p. 4; KB4 sample email.
- **Class:** `computable`: `from_name`, and the closing lines of `body_text`.
- **Decide:** fire when the display name or sign-off matches a list of role
  names (seeds in section 4). **Misfire:** real mail from real HR, IT and
  management mailboxes.
- **Note:** this is the decidable fragment of `poses_as_trusted_party`. It
  describes a disguise, not a defect.

#### `poses_as_trusted_party`

- **Cue:** The mail presents itself as coming from someone the reader trusts:
  a friend, a colleague, a boss, a known company or an authority.
- **Sources:** NIST Table 2 (p. 9), B.5.6 (pp. 36-37), section 2.2.1 element 2
  (p. 11); CISA-GUIDE pp. 4-5; CISA-RRP, "Don't Take the Bait"; CISA-ASE,
  "What is a phishing attack?"; FTC, "How To Recognize Phishing" (intro).
- **Class:** `not computable`. **Missing:** who this reader trusts, and
  whether the claimed identity is false. Both are judgments. The decidable
  fragments are `display_name_address_mismatch`, the three
  `domain_lookalike_*` cues, `brand_name_in_freemail_sender` and
  `authority_role_sender_name`.

#### `known_sender_out_of_character`

- **Cue:** Mail from a sender the reader does know, such as a colleague,
  customer, vendor or partner, that is very unlike what that sender normally
  sends. The account may have been taken over.
- **Sources:** KB4 FROM 3; CISA-TEA step 1.
- **Class:** `not computable`. **Missing:** a record of what each sender
  normally writes. The daemon keeps only whether a sender has been seen.

#### `external_sender_unrelated_to_job`

- **Cue:** The sender is outside the reader's organization and the mail has
  nothing to do with the reader's work.
- **Sources:** KB4 FROM 2.
- **Class:** `not computable`. **Missing:** a judgment about relevance to the
  reader's job. The "outside my organization" half is decidable on its own
  (`from_addr` domain against the reader's), but in a personal mailbox it is
  true of almost every sender.

#### `sender_authentication_failure`

- **Cue:** The sending server is not one the claimed domain authorizes, so
  the From address is forged. This includes forgery of an exact,
  legitimate-looking domain.
- **Sources:** CISA-GUIDE p. 6 (SPF, DKIM and DMARC checks on received mail);
  NIST B.2.4, first example (p. 31), where a From address at a
  reputable-looking domain counts as domain spoofing.
- **Class:** `not computable`. **Missing:** authentication results, which
  live in raw headers.

### 3.2 Recipients, subject and timing

#### `recipients_unknown_to_user`

- **Cue:** The reader is one of several recipients and does not know the
  others.
- **Sources:** KB4 TO 1.
- **Class:** `needs history`: seen-sender set, looked up for each other
  address in `to`.
- **Decide:** fire when there are other recipients and none of them is in the
  seen-sender set. **Misfire:** announcements and group mail to people who
  have never written to the reader.
- **Note:** the set records senders, not acquaintances, so this is an
  approximation of "know".

#### `recipients_unusual_mix`

- **Cue:** The mail went to an odd assortment of recipients, for example an
  alphabetical slice of an organization's directory or a long list of
  unrelated addresses.
- **Sources:** KB4 TO 2.
- **Class:** `computable`: `to`.
- **Decide:** fire on the two shapes the source names: many recipients spread
  across unrelated domains, or several same-domain recipients that sit
  together alphabetically. **Misfire:** club or community mail sent with
  every recipient visible, and small teams whose names happen to sort
  together.
- **Note:** the source's alphabetical example is about last names, which an
  address need not start with. Anything else "unusual" is a judgment.

#### `reply_to_unsent_message`

- **Cue:** The mail is framed as a reply to something the reader never sent
  or asked for.
- **Sources:** KB4 SUBJECT 2.
- **Class:** `needs history`: seen-sender set, as a stand-in for the reader's
  sent mail, which is not available.
- **Decide:** fire when `subject` starts with the reply marker "Re: "
  (RFC 5322 section 3.6.5) and the sender has never been seen. **Misfire:**
  the first honest reply from someone the reader wrote to, such as an answer
  to an inquiry or a web form.

#### `sent_at_unusual_hour`

- **Cue:** Mail of a kind that normally arrives in business hours was sent at
  an odd time, such as 3 a.m.
- **Sources:** KB4 DATE 1.
- **Class:** `not computable`. **Missing:** the send time, which is not among
  the observation fields, and each sender's normal hours and time zone.

### 3.3 Links

#### `link_text_target_mismatch`

- **Cue:** The visible text of a link is a web address, and the link goes to
  a different site.
- **Sources:** NIST section 2.1.3 (p. 8), B.2.3 (p. 30); KB4 HYPERLINKS 1;
  CISA-ASE indicator 3.
- **Class:** `computable`: `links[].text`, `links[].href`.
- **Decide:** fire when the link text parses as a URL or domain and its
  registrable domain differs from the target's. **Misfire:** click tracking
  and link rewriting, where the text shows the real site and the target is a
  redirect service run by a newsletter platform or a mail security gateway.

#### `link_text_hides_url`

- **Cue:** A link's visible text is words rather than the address, so the
  destination is hidden until the reader hovers over it.
- **Sources:** NIST Table 2 (p. 9), B.2.3 (p. 30), Appendix B Figure 2
  (p. 31), worksheet A.1 part 2 (p. 23).
- **Class:** `computable`: `links[].text`, `links[].href`.
- **Decide:** count the links whose text is not a URL. **Misfire:** worded
  links and buttons are normal in honest HTML mail, so expect this to fire
  widely.
- **Note:** NIST's example of text that names one organization while the link
  goes to another (B.2.3) would need a mapping from organization names to
  domains, and is not decided here.

#### `link_shortened_url`

- **Cue:** A link goes through a URL-shortening service, which hides where it
  ends up.
- **Sources:** CISA-RRP "Recognize" item 3; CISA-TIP p. 1, sign 4; CISA-ASE
  indicator 3.
- **Class:** `computable`: `links[].href`, with a list of shortener hosts.
- **Decide:** fire when a link's target host is on the shortener list.
  **Misfire:** honest senders use shorteners too. CISA limits the sign to
  "untrusted" ones, which is a judgment.
- **Note:** no source read supplies a list of shortener hosts. One has to be
  chosen and cited separately.

#### `link_only_body`

- **Cue:** The mail is nothing but one or more long links, with no other
  text.
- **Sources:** KB4 HYPERLINKS 2.
- **Class:** `computable`: `body_text`, `links`.
- **Decide:** fire when `body_text` is empty once link text and URLs are
  removed. **Misfire:** a friend or colleague passing on a bare link.

#### `link_target_high_risk_file`

- **Cue:** A link leads straight to a download of an executable file.
- **Sources:** CISA-GUIDE p. 5 (links that download executables), with the
  extension lists at pp. 7 and 9.
- **Class:** `computable`: `links[].href`.
- **Decide:** fire when the path of a link target ends in an extension from
  the list under `attachment_high_risk_type`. **Misfire:** honest software
  download links.
- **Note:** a narrow reading of the source. Only a file name visible in the
  URL can fire; a link that redirects to a download cannot.

#### `link_to_fake_login_page`

- **Cue:** A link leads to a page that imitates a real login page in order to
  collect the reader's credentials.
- **Sources:** CISA-GUIDE p. 4; CISA-RRP, "Omar" story.
- **Class:** `not computable`. **Missing:** the content of the page behind
  the link, which is known only once the page is open. That is the page
  sensor's job. The wording of the request is covered by
  `request_sensitive_information`.

### 3.4 Attachments

#### `attachment_present`

- **Cue:** The mail carries an attachment. NIST counts any attachment type;
  KnowBe4 treats every type except `.txt` as possibly dangerous.
- **Sources:** NIST Table 2 (p. 9), B.2.1 (p. 30), worksheet A.1 part 2
  (p. 23); KB4 ATTACHMENTS 2.
- **Class:** `computable`: `attachments`.
- **Decide:** fire when there is at least one attachment, or under KnowBe4's
  narrowing, one whose name does not end in `.txt`. **Misfire:** all ordinary
  mail with attachments.

#### `attachment_high_risk_type`

- **Cue:** An attachment is of a type that runs code when opened.
- **Sources:** CISA-GUIDE p. 7 and p. 9; NIST B.2.1 (p. 30), which lists
  executables among its examples; KB4 ATTACHMENTS 2.
- **Class:** `computable`: `attachments`, with a list of extensions.
- **Decide:** fire when the last extension of an attachment name is on the
  list (sourced extensions in section 4). **Misfire:** developers and IT
  staff who exchange installers and scripts.

#### `attachment_from_unseen_sender`

- **Cue:** An attachment the reader was not expecting, from someone they do
  not correspond with.
- **Sources:** KB4 FROM 7, ATTACHMENTS 1; CISA-TIP p. 1, sign 3; CISA-ASE
  indicator 5.
- **Class:** `needs history`: seen-sender set. Field: `attachments`.
- **Decide:** fire when there is an attachment and the sender has never been
  seen. **Misfire:** the first invoice, contract or form from a new supplier,
  recruiter or school.
- **Note:** "unexpected" is otherwise a judgment.

#### `attachment_type_differs_from_body_mention`

- **Cue:** The body names one file type and the attached file is another.
- **Sources:** NIST B.1.2 (p. 29) and Appendix B Figure 1 (p. 29).
- **Class:** `computable`: `body_text`, `attachments`.
- **Decide:** fire when `body_text` names a file extension and no attachment
  has it. **Misfire:** a body that mentions a file type in passing, or that
  refers to a file behind a link.

#### `attachment_mislabeled_type`

- **Cue:** An attachment's extension misstates what the file is, such as an
  executable labeled as a document.
- **Sources:** CISA-GUIDE p. 7.
- **Class:** `not computable`. **Missing:** the file's content; the sensor
  sees only its name. A name with two extensions would be one visible form,
  but no source read names that form, so it is not proposed here.

#### `attachment_with_macros`

- **Cue:** An attached document carries macro scripts.
- **Sources:** CISA-GUIDE pp. 5 and 8.
- **Class:** `not computable`. **Missing:** the file's content. Judging by
  extension would need a list of macro-capable file types, which no source
  read supplies.

#### `attachment_out_of_place`

- **Cue:** An attachment that makes no sense for the message, or that this
  sender does not normally send.
- **Sources:** KB4 ATTACHMENTS 1.
- **Class:** `not computable`. **Missing:** a judgment about relevance, and a
  per-sender record of attachment types, which the daemon does not keep.

### 3.5 Language and content

Unless an entry says otherwise, the fields are `subject` and `body_text` and
the decision is a match against a phrase list whose sourced seeds are in
section 4.

#### `urgency`

- **Cue:** The mail presses the reader to act at once, by an explicit
  deadline or by wording that demands immediate action.
- **Sources:** NIST Table 2 (p. 9), B.4.4 (p. 34), Appendix B Figure 4
  (p. 35); KB4-blog, "Stressor Events"; CISA-RRP "Recognize" item 1 and
  "Omar" story; CISA-TIP p. 1, sign 1; CISA-ASE indicator 5; CISA-TEA step 1.
- **Class:** `computable`.
- **Decide:** phrase list. **Misfire:** honest deadlines, such as payment due
  dates, expiring codes, meeting reminders and sales.

#### `threat_of_consequence`

- **Cue:** The mail states or implies that something bad will happen if the
  reader does not act: an account closed, a penalty, legal or disciplinary
  action.
- **Sources:** NIST Table 2 (p. 9), B.4.5 (p. 34), Appendix B Figure 4
  (p. 35), section 2.2.1 element 4 (p. 12); KB4 CONTENT 1; KB4-blog,
  "Stressor Events"; CISA-RRP "Recognize" item 1.
- **Class:** `computable`.
- **Decide:** phrase list. **Misfire:** honest service notices that warn of
  suspension, expiry or late fees.

#### `request_sensitive_information`

- **Cue:** The mail asks for credentials or for personal, identity or
  financial details.
- **Sources:** NIST Table 2 (p. 9), B.4.3 (p. 34), Appendix B Figure 4
  (p. 35); CISA-RRP "Recognize" item 2; CISA-TIP p. 1, sign 2; CISA-ASE,
  "What is a phishing attack?"; CISA-GUIDE p. 4; KB4-blog, list of unexpected
  requests; FTC list item 3.
- **Class:** `computable`.
- **Decide:** phrase list. **Misfire:** password resets and verification
  mails the reader asked for, and onboarding, tax and bank forms.

#### `request_payment`

- **Cue:** The mail asks the reader to pay, send money, buy gift cards, or
  change payment, bank or payroll details.
- **Sources:** KB4 sample email; KB4-blog, list of unexpected requests; FTC
  list item 5, example sign 3 and the section's closing sentence.
- **Class:** `computable`.
- **Decide:** phrase list. **Misfire:** honest invoices, renewals and payment
  reminders.

#### `account_problem_claim`

- **Cue:** The mail claims something is wrong with the reader's account,
  payment, order or sign-in activity, and offers a way to fix it.
- **Sources:** FTC list items 1 and 2, example sign 2; CISA-ASE, "What is a
  phishing attack?"; CISA-TIP p. 2 (sample); CISA-RRP, "Omar" story.
- **Class:** `computable`.
- **Decide:** phrase list. **Misfire:** honest security alerts and
  failed-payment notices from services the reader uses.

#### `click_or_open_request`

- **Cue:** The mail tells the reader to click a link, or to open or download
  an attachment.
- **Sources:** KB4 CONTENT 1 and 3; KB4-blog, list of unexpected requests;
  CISA-ASE indicator 5; CISA-TIP p. 2 (sample).
- **Class:** `computable`.
- **Decide:** phrase list. **Misfire:** newsletters, receipts and
  notifications use the same wording.
- **Note:** KB4 CONTENT 1 counts it only together with a threat or a reward,
  and CONTENT 3 only when the request seems odd.

#### `generic_greeting`

- **Cue:** The mail has no greeting, or greets the reader without their name.
- **Sources:** NIST Table 2 (p. 9), B.4.6 (p. 34), worksheet A.1 part 1
  (p. 22); CISA-ASE indicator 2; CISA-TIP p. 2 (sample); FTC example sign 1.
- **Class:** `computable`: the opening lines of `body_text`.
- **Decide:** fire when the opening matches a list of generic salutations, or
  the first lines hold no salutation. **Misfire:** automated notifications
  and newsletters.
- **Note:** the reverse does not hold. CISA-TEA step 1 warns that attackers
  add personal and company details, so a named greeting is no sign of safety.

#### `missing_signer_details`

- **Cue:** The mail ends without a named signer, or without contact details
  such as a title, phone number or address.
- **Sources:** NIST Table 2 (p. 9), B.4.7 (p. 35), worksheet A.1 part 1
  (p. 22); CISA-ASE indicator 2.
- **Class:** `computable`: the closing lines of `body_text`.
- **Decide:** fire when the closing lines hold no phone number, email address
  or postal address. **Misfire:** short personal mails and quick replies,
  which rarely carry a signature block.

#### `signature_name_differs_from_sender`

- **Cue:** The name in the sign-off is not the sender named in the From line.
- **Sources:** NIST B.1.2 (p. 29).
- **Class:** `computable`: the closing lines of `body_text`, `from_name`,
  `from_addr`.
- **Decide:** fire when the sign-off name shares no word with the display
  name or the address. **Misfire:** assistants, shared mailboxes and
  nicknames.
- **Note:** finding the sign-off in plain text is itself uncertain.

#### `legal_boilerplate`

- **Cue:** The mail carries legal-style text: a copyright or trademark
  notice, a disclaimer, a security warning, tax wording.
- **Sources:** NIST Table 2 (p. 9), B.4.1 (p. 33), Appendix B Figure 4
  (p. 35), worksheet A.1 part 2 (p. 23).
- **Class:** `computable`.
- **Decide:** phrase list. **Misfire:** honest commercial mail commonly
  carries such a footer.
- **Note:** NIST lists this as a cue without saying which way it points, so
  the sign of its weight is a question for measurement.

#### `security_indicator_text`

- **Cue:** The body asserts its own security, with wording such as a signing
  or verification claim or a security endorsement.
- **Sources:** NIST Table 2 (p. 9), B.3.4 (p. 32), worksheet A.1 part 2
  (p. 23).
- **Class:** `computable`: `body_text`, for the wording only.
- **Decide:** phrase list. **Misfire:** honest signed-mail notices and
  security banners.
- **Note:** the padlock icons and images that NIST also counts under this cue
  are not visible to the sensor.

#### `too_good_to_be_true_offer`

- **Cue:** The mail offers an unexpected prize, refund, free goods or other
  gain.
- **Sources:** NIST Table 2 (p. 9), B.5.2 (p. 36), Appendix B Figure 5
  (p. 37); KB4 CONTENT 1; CISA-RRP, "Resist"; FTC list items 6 and 7.
- **Class:** `computable`.
- **Decide:** phrase list. **Misfire:** honest promotions, loyalty rewards
  and real refunds.

#### `exclusive_offer_for_you`

- **Cue:** The mail offers something unexpected and special meant only for
  the reader, such as an e-card or a personal coupon.
- **Sources:** NIST Table 2 (p. 9), B.5.3 (p. 36), Appendix B Figure 5
  (p. 37).
- **Class:** `computable`.
- **Decide:** phrase list. **Misfire:** honest birthday coupons, greeting
  cards and loyalty offers.

#### `limited_time_offer`

- **Cue:** The mail attaches an expiry date or a short window to something it
  offers.
- **Sources:** NIST Table 2 (p. 9), B.5.4 (p. 36), Appendix B Figure 5
  (p. 37).
- **Class:** `computable`.
- **Decide:** phrase list for an offer together with an expiry. **Misfire:**
  every honest sale with an end date.
- **Note:** NIST counts this only when something is offered. Plain time
  pressure is `urgency`.

#### `humanitarian_appeal`

- **Cue:** The mail appeals to the reader's wish to help: a charity, a
  disaster, someone in need.
- **Sources:** NIST Table 2 (p. 9), B.5.1 (p. 35), Appendix B Figure 5
  (p. 37); CISA-ASE, "What is a phishing attack?".
- **Class:** `computable`.
- **Decide:** phrase list. **Misfire:** honest charity appeals and
  fundraising newsletters.

#### `mimics_business_process`

- **Cue:** The mail is dressed as a routine business notification: a
  voicemail, a delivery, an order confirmation, an invoice.
- **Sources:** NIST Table 2 (p. 9), B.5.5 (p. 36), Appendix B Figures 1 and 2
  (pp. 29 and 31); FTC list item 4; KB4-blog, list of unexpected requests;
  CISA-RRP, "Omar" story; CISA-TIP p. 2 (sample).
- **Class:** `computable`.
- **Decide:** list of process names. **Misfire:** the real notifications of
  exactly these kinds. On its own this marks a category of mail, not a fault.

#### `compromising_picture_lure`

- **Cue:** The mail invites the reader to look at an embarrassing or
  compromising picture of themselves or of someone they know.
- **Sources:** KB4 CONTENT 5.
- **Class:** `computable`.
- **Decide:** phrase list; no source supplies a phrase. **Misfire:** friends
  sharing photos with teasing captions.

#### `spelling_errors`

- **Cue:** The mail contains misspelled words.
- **Sources:** NIST section 2.1.3 (p. 8), Table 2 (p. 9), B.1.1 (p. 29),
  Appendix B Figure 1 (p. 29); KB4 CONTENT 2; CISA-ASE indicator 4; CISA-TIP
  p. 1, sign 6; CISA-RRP, the paragraph under the "Recognize" list.
- **Class:** `computable`, given a word list for the mail's language.
- **Decide:** fire when the share of words not found in the word list passes
  a threshold. **Misfire:** names, product names, jargon, mixed-language mail
  and ordinary typos.
- **Note:** CISA-TIP calls this sign "less common", and CISA-RRP says
  AI-written phishing may show none.

#### `grammar_errors`

- **Cue:** The mail contains grammar or punctuation errors, a correctly
  spelled wrong word, or a mismatch such as "we" above a single signer.
- **Sources:** NIST Table 2 (p. 9), B.1.1 (p. 29), Appendix B Figure 1
  (p. 29); KB4 CONTENT 2; CISA-ASE indicator 4.
- **Class:** `not computable`. **Missing:** language analysis beyond looking
  words up in a list.

#### `distracting_detail`

- **Cue:** The mail contains detail that has nothing to do with its main
  point.
- **Sources:** NIST Table 2 (p. 9), B.4.2 (p. 33), Appendix B Figure 4
  (p. 35).
- **Class:** `not computable`. **Missing:** a judgment about what the
  message's main point is.

#### `content_inconsistency`

- **Cue:** Parts of the mail do not fit together, for example a subject line
  that does not match the body.
- **Sources:** NIST Table 2 (p. 9), B.1.2 (p. 29); KB4 SUBJECT 1.
- **Class:** `not computable`. **Missing:** a judgment about meaning. The two
  forms NIST names are decidable and have their own entries:
  `attachment_type_differs_from_body_mention` and
  `signature_name_differs_from_sender`.

#### `odd_or_illogical_request`

- **Cue:** The mail, or what it asks for, is out of the ordinary for this
  reader: a strange, unexpected or illogical request.
- **Sources:** KB4 CONTENT 2 and 3; KB4-blog, the "unexpected requests"
  paragraph; CISA-TEA step 1.
- **Class:** `not computable`. **Missing:** a judgment about what is ordinary
  for this reader.

#### `current_event_theme`

- **Cue:** The mail ties itself to something in the news or the calendar: a
  disaster, an epidemic, a tax deadline, an election, a holiday.
- **Sources:** CISA-ASE, "What is a phishing attack?"; NIST section 2.2.1
  element 3 (p. 12).
- **Class:** `not computable`. **Missing:** knowledge of what is current. A
  fixed list would go stale.

#### `gut_feeling`

- **Cue:** The reader feels uneasy about the request.
- **Sources:** KB4 CONTENT 4.
- **Class:** `not computable`. **Missing:** the reader. There is nothing to
  observe.

### 3.6 Appearance

#### `missing_branding`

- **Cue:** Branding that the supposed sender would normally use, such as a
  logo, banner or brand typeface, is absent.
- **Sources:** NIST Table 2 (p. 9), B.3.1 (p. 32), worksheet A.1 part 1
  (p. 22).
- **Class:** `not computable`. **Missing:** rendered appearance and images.

#### `imitated_or_outdated_branding`

- **Cue:** Logos or other branding look like imitations or are out of date.
- **Sources:** NIST Table 2 (p. 9), B.3.2 (p. 32), worksheet A.1 part 2
  (p. 23).
- **Class:** `not computable`. **Missing:** images and logos, and knowledge
  of the real brand's current look.

#### `unprofessional_design`

- **Cue:** Layout and formatting look amateur: odd line breaks, stray
  highlighting, inconsistent formatting.
- **Sources:** NIST Table 2 (p. 9), B.3.3 (p. 32), worksheet A.1 part 1
  (p. 22); CISA-ASE indicator 4.
- **Class:** `not computable`. **Missing:** rendered appearance.

## 4. Seed phrases

Only wording that a source itself gives is listed. Two kinds:

- **sample**: text inside an example message that the source shows
- **named**: a word, item or short description that the source offers as an
  example of the cue, outside any example message

The sources are in English, so every seed is English. These are seeds, not
working lists: a phrase list for any of these cues has to be derived from
measurement. FTC wording came through a fetch tool (section 1).

NIST's figures mark which cue each boxed phrase illustrates, and its phrases
are filed under that cue unless the row says otherwise. KnowBe4's and CISA's
sample emails carry no such marking, so filing their phrases under a cue is
this catalog's reading.

| Cue | Phrase | Kind | Source |
|---|---|---|---|
| `urgency` | "immediately" | named | NIST B.4.4 (p. 34); also boxed as urgency in a sample, Appendix B Figure 4 (p. 35) |
| `urgency` | "URGENT" | sample, subject | CISA-TIP p. 2 |
| `urgency` | "must be verified now" | named | KB4-blog, "Stressor Events" |
| `threat_of_consequence` | "disciplinary action may be taken" | sample | NIST Appendix B Figure 4 (p. 35) |
| `threat_of_consequence` | "permanently locked" | named | KB4-blog, "Stressor Events" |
| `request_sensitive_information` | "your network credentials" | sample | NIST Appendix B Figure 4 (p. 35) |
| `request_sensitive_information` | "login credentials", "social security number" | named | NIST B.4.3 (p. 34) |
| `request_sensitive_information` | "account information" | named | CISA-ASE, "What is a phishing attack?" |
| `request_sensitive_information` | "confirm some personal or financial information" | named | FTC list item 3 |
| `request_payment` | "wire me $300" | sample | KB4 sample email |
| `request_payment` | "Process an invoice", "Change banking or payroll information", "Buy gift cards" | named | KB4-blog, list of unexpected requests |
| `request_payment` | "make a payment", "update your payment details" | named | FTC list item 5; example sign 3 |
| `account_problem_claim` | "There is a problem with your recent order." | sample | CISA-TIP p. 2 |
| `account_problem_claim` | "suspicious activity or log-in attempts" | named | FTC list item 1 |
| `account_problem_claim` | "a problem with your account or your payment information" | named | FTC list item 2 |
| `account_problem_claim` | "your account is on hold because of a billing problem" | named | FTC example sign 2 |
| `click_or_open_request` | "Please click here" | sample | CISA-TIP p. 2 |
| `generic_greeting` | "Dear Valued Customer", "Sir/Ma'am" | named | CISA-ASE indicator 2 |
| `generic_greeting` | "Dear user," | sample | CISA-TIP p. 2 |
| `legal_boilerplate` | "Do not reply to this email." | sample | NIST Appendix B Figure 4 (p. 35) |
| `security_indicator_text` | "digitally signed" | named | NIST B.3.4 (p. 32) |
| `too_good_to_be_true_offer` | "FREE", "Gift Certificate has arrived!" | sample, two parts of one boxed line | NIST Appendix B Figure 5 (p. 37) |
| `too_good_to_be_true_offer` | "contest", "lottery", "free vacation" | named | NIST Table 2 (p. 9) |
| `too_good_to_be_true_offer` | "a government refund", "a coupon for free stuff" | named | FTC list items 6 and 7 |
| `exclusive_offer_for_you` | "Your Restaurant Gift Certificate is here!" | sample, subject | NIST Appendix B Figure 5 (p. 37) |
| `exclusive_offer_for_you` | "a valentine e-card", "a special birthday coupon" | named | NIST B.5.3 (p. 36) |
| `limited_time_offer` | "Offer expires in 14 days" | sample | NIST Appendix B Figure 5 (p. 37) |
| `humanitarian_appeal` | "donate your gift certificate to a family in need" | sample | NIST Appendix B Figure 5 (p. 37) |
| `mimics_business_process` | "voicemail notification", "package delivery" | named | NIST B.5.5 (p. 36) |
| `mimics_business_process` | "new voicemail", "order confirmation", "notice of invoice" | named | NIST Table 2 (p. 9) |
| `mimics_business_process` | "Unpaid invoice" | sample, subject; not boxed, but B.5.5 names this email's premise as an example | NIST Appendix B Figure 1 (p. 29); B.5.5 (p. 36) |
| `mimics_business_process` | "Unauthorized Web Site Access" | sample, subject; not boxed, but B.5.5 names this email's premise as an example | NIST Appendix B Figure 2 (p. 31); B.5.5 (p. 36) |
| `mimics_business_process` | "Your Recent Order" | sample, subject | CISA-TIP p. 2 |
| `authority_role_sender_name` | "Human Resources" | sample, From name | NIST Appendix B Figure 5 (p. 37) |
| `authority_role_sender_name` | "System Administrator" | sample, From name; NIST marks it for the display-name cue | NIST Appendix B Figure 2 (p. 31) |
| `authority_role_sender_name` | "IT Helpdesk" | named | NIST B.2.2 (p. 30) |
| `authority_role_sender_name` | "Your CEO" | sample, sign-off | KB4 sample email |
| `compromising_picture_lure` | no sourced phrases; to be derived from measurement | | |

### Sourced examples that are not phrases

These come from the same documents and can serve as test inputs for the
non-language cues.

| Cue | Example | Source |
|---|---|---|
| `domain_lookalike_misspelling` | `micorsoft-support.com` | KB4 FROM 4 |
| `domain_lookalike_misspelling` | `www.bankofarnerica.com`, "rn" standing in for "m" | KB4 HYPERLINKS 3 |
| `domain_lookalike_misspelling` | `amazan.com` | CISA-RRP "Recognize" item 4; CISA-TIP p. 2 |
| `domain_lookalike_misspelling` | `www.niist.gov` and `www.ni-st.gov`, for `nist.gov` | NIST section 2.1.3 (p. 8); B.2.4 (p. 31) |
| `domain_lookalike_suffix_swap` | `www.nist.com`, for `nist.gov` | NIST B.2.4 (p. 31) |
| `domain_lookalike_suffix_swap` | ".com vs. .net" | CISA-ASE indicator 3 |
| `domain_lookalike_embedded` | `google.com.rogueserver.biz`, `amazongproducts.ru` | KB4-blog, "Number One Most Suspicious Sign" |
| `brand_name_in_freemail_sender` | `microsoftustechsupport@outlook.com` | KB4-blog, "Number One Most Suspicious Sign" |
| `display_name_address_mismatch` | display name "IT Helpdesk", reply-to `accounts-payable@gmail.com` | NIST B.2.2 (p. 30) |
| `link_text_target_mismatch` | text `www.niist.gov`, target `commerce.gov` | NIST section 2.1.3 (p. 8) |
| `link_text_hides_url` | text "Department of Defense", target `www.nist.gov` | NIST B.2.3 (p. 30) |
| `attachment_high_risk_type` | `.scr`, `.exe`, `.pif`, `.cpl` | CISA-GUIDE p. 7 |
| `attachment_high_risk_type` | `.exe`, `.scr` | CISA-GUIDE p. 9 |
| `attachment_present` | `.jpeg`, `.pdf`, `.exe`, `.zip`, as examples of attachment types | NIST B.2.1 (p. 30) |
| `attachment_present` | `.txt`, as the one type called always safe | KB4 ATTACHMENTS 2 |
| `attachment_type_differs_from_body_mention` | body says `.doc`, attached file is `.zip` | NIST Appendix B Figure 1 (p. 29) |
| `spelling_errors` | "paymen" | NIST Appendix B Figure 1 (p. 29) |
| `grammar_errors` | "compliment" used for "complement" | NIST B.1.1 (p. 29) |

Three things the examples show:

- `micorsoft-support.com` and `amazongproducts.ru` both add characters to the
  known name. A check for a single edit against the whole name does not catch
  either.
- Only four high-risk attachment extensions are sourced. `.zip` is named by
  NIST as an example of an attachment type, not as a high-risk one.
- The sample email in NIST Appendix B Figure 5 (p. 37) contains a
  `tinyurl.com` address inside the text NIST marks as the humanitarian appeal.
  NIST does not mark it as a link cue, so it is not a sourced shortener host.

## 5. Summary

| Classification | Entries |
|---|---|
| `computable` | 29 |
| `needs history` | 8 |
| `not computable` | 18 |
| Total | 55 |

The source columns show which publishers state the cue: N for NIST, K for
KnowBe4 (infographic or blog post), C for any CISA document, F for FTC.

### `computable` (29)

| Id | Fields | N | K | C | F |
|---|---|---|---|---|---|
| `display_name_address_mismatch` | `from_name`, `from_addr`, `reply_to` | x | | x | |
| `authority_role_sender_name` | `from_name`, `body_text` | x | x | x | |
| `recipients_unusual_mix` | `to` | | x | | |
| `link_text_target_mismatch` | `links` | x | x | x | |
| `link_text_hides_url` | `links` | x | | | |
| `link_shortened_url` | `links` | | | x | |
| `link_only_body` | `body_text`, `links` | | x | | |
| `link_target_high_risk_file` | `links` | | | x | |
| `attachment_present` | `attachments` | x | x | | |
| `attachment_high_risk_type` | `attachments` | x | x | x | |
| `attachment_type_differs_from_body_mention` | `body_text`, `attachments` | x | | | |
| `urgency` | `subject`, `body_text` | x | x | x | |
| `threat_of_consequence` | `subject`, `body_text` | x | x | x | |
| `request_sensitive_information` | `subject`, `body_text` | x | x | x | x |
| `request_payment` | `subject`, `body_text` | | x | | x |
| `account_problem_claim` | `subject`, `body_text` | | | x | x |
| `click_or_open_request` | `subject`, `body_text` | | x | x | |
| `generic_greeting` | `body_text` | x | | x | x |
| `missing_signer_details` | `body_text` | x | | x | |
| `signature_name_differs_from_sender` | `body_text`, `from_name`, `from_addr` | x | | | |
| `legal_boilerplate` | `subject`, `body_text` | x | | | |
| `security_indicator_text` | `body_text` | x | | | |
| `too_good_to_be_true_offer` | `subject`, `body_text` | x | x | x | x |
| `exclusive_offer_for_you` | `subject`, `body_text` | x | | | |
| `limited_time_offer` | `subject`, `body_text` | x | | | |
| `humanitarian_appeal` | `subject`, `body_text` | x | | x | |
| `mimics_business_process` | `subject`, `body_text` | x | x | x | x |
| `compromising_picture_lure` | `subject`, `body_text` | | x | | |
| `spelling_errors` | `subject`, `body_text` | x | x | x | |

### `needs history` (8)

| Id | History | Fields | N | K | C | F |
|---|---|---|---|---|---|---|
| `domain_lookalike_misspelling` | login-domain set | `from_addr`, `links` | x | x | x | |
| `domain_lookalike_suffix_swap` | login-domain set | `from_addr`, `links` | x | | x | |
| `domain_lookalike_embedded` | login-domain set | `from_addr`, `links` | | x | | |
| `brand_name_in_freemail_sender` | login-domain set | `from_addr` | | x | | |
| `sender_never_seen` | seen-sender set | `from_addr` | | x | | |
| `recipients_unknown_to_user` | seen-sender set | `to` | | x | | |
| `reply_to_unsent_message` | seen-sender set | `subject`, `from_addr` | | x | | |
| `attachment_from_unseen_sender` | seen-sender set | `from_addr`, `attachments` | | x | x | |

### `not computable` (18)

| Id | Missing |
|---|---|
| `poses_as_trusted_party` | who the reader trusts; whether the identity is false |
| `known_sender_out_of_character` | what each sender normally writes |
| `external_sender_unrelated_to_job` | relevance to the reader's job |
| `sender_authentication_failure` | authentication results from raw headers |
| `sent_at_unusual_hour` | send time; each sender's normal hours |
| `link_to_fake_login_page` | content of the linked page |
| `attachment_mislabeled_type` | file content |
| `attachment_with_macros` | file content |
| `attachment_out_of_place` | relevance; per-sender attachment record |
| `grammar_errors` | language analysis |
| `distracting_detail` | what the message's main point is |
| `content_inconsistency` | meaning of subject and body |
| `odd_or_illogical_request` | what is ordinary for this reader |
| `current_event_theme` | what is current |
| `gut_feeling` | the reader |
| `missing_branding` | rendered appearance and images |
| `imitated_or_outdated_branding` | images and logos |
| `unprofessional_design` | rendered appearance |

## 6. Coverage

### 6.1 NIST TN 2276: the 23 cues

Cue names and types are those of NIST Table 1 (p. 6).

| # | NIST cue | Type | Entries | Outcome |
|---|---|---|---|---|
| 1 | Spelling and grammar irregularities | Error | `spelling_errors`, `grammar_errors` | `computable` in part: spelling only |
| 2 | Inconsistency | Error | `attachment_type_differs_from_body_mention`, `signature_name_differs_from_sender`, `content_inconsistency` | `computable` in part: the two forms NIST names |
| 3 | Attachment type | Technical indicator | `attachment_present`, `attachment_high_risk_type` | `computable` |
| 4 | Sender display name and email address | Technical indicator | `display_name_address_mismatch` | `computable` |
| 5 | URL hyperlinking | Technical indicator | `link_text_target_mismatch`, `link_text_hides_url` | `computable` |
| 6 | Domain spoofing | Technical indicator | `domain_lookalike_misspelling`, `domain_lookalike_suffix_swap`, `sender_authentication_failure` | `needs history`; forgery of the exact domain is `not computable` |
| 7 | No/minimal branding and logos | Visual presentation indicator | `missing_branding` | `not computable` |
| 8 | Logo imitation or out-of-date branding/logos | Visual presentation indicator | `imitated_or_outdated_branding` | `not computable` |
| 9 | Unprofessional looking design or formatting | Visual presentation indicator | `unprofessional_design` | `not computable` |
| 10 | Security indicators and icons | Visual presentation indicator | `security_indicator_text` | `computable` in part: wording only, not icons |
| 11 | Legal language/copyright info/disclaimers | Language and content | `legal_boilerplate` | `computable` |
| 12 | Distracting detail | Language and content | `distracting_detail` | `not computable` |
| 13 | Requests for sensitive information | Language and content | `request_sensitive_information` | `computable` |
| 14 | Sense of urgency | Language and content | `urgency` | `computable` |
| 15 | Threatening language | Language and content | `threat_of_consequence` | `computable` |
| 16 | Generic greeting | Language and content | `generic_greeting` | `computable` |
| 17 | Lack of signer details | Language and content | `missing_signer_details` | `computable` |
| 18 | Humanitarian appeals | Common tactic | `humanitarian_appeal` | `computable` |
| 19 | Too good to be true offers | Common tactic | `too_good_to_be_true_offer` | `computable` |
| 20 | You're special | Common tactic | `exclusive_offer_for_you` | `computable` |
| 21 | Limited time offer | Common tactic | `limited_time_offer` | `computable` |
| 22 | Mimics a work or business process | Common tactic | `mimics_business_process` | `computable` |
| 23 | Poses as friend, colleague, supervisor, authority figure | Common tactic | `authority_role_sender_name`, `poses_as_trusted_party` | `computable` in part: role names only |

Tally of the 23: `computable` 14 (rows 3, 4, 5, 11, 13 to 22); `computable` in
part 4 (rows 1, 2, 10, 23); `needs history` 1 (row 6); `not computable` 4
(rows 7, 8, 9, 12).

### 6.2 KnowBe4: the 22 red flags

| Red flag | Entries | Classification |
|---|---|---|
| FROM 1, sender not someone I ordinarily communicate with | `sender_never_seen` | `needs history` |
| FROM 2, outside my organization and unrelated to my job | `external_sender_unrelated_to_job` | `not computable` |
| FROM 3, known sender, out of character | `known_sender_out_of_character` | `not computable` |
| FROM 4, suspicious sender domain | `domain_lookalike_misspelling`, `domain_lookalike_embedded` | `needs history` |
| FROM 5, do not know the sender, not vouched for | `sender_never_seen` | `needs history`; "vouched for" has nothing to observe |
| FROM 6, no business relationship or past communication | `sender_never_seen` | `needs history` |
| FROM 7, unexpected link or attachment from someone not in recent contact | `sender_never_seen`, `attachment_from_unseen_sender` | `needs history` |
| TO 1, other recipients I do not know | `recipients_unknown_to_user` | `needs history` |
| TO 2, unusual mix of recipients | `recipients_unusual_mix` | `computable` |
| HYPERLINKS 1, link goes to a different site than shown | `link_text_target_mismatch` | `computable` |
| HYPERLINKS 2, only long links, otherwise blank | `link_only_body` | `computable` |
| HYPERLINKS 3, link is a misspelling of a known site | `domain_lookalike_misspelling` | `needs history` |
| DATE 1, sent at an unusual time | `sent_at_unusual_hour` | `not computable` |
| SUBJECT 1, subject irrelevant or does not match the content | `content_inconsistency` | `not computable` |
| SUBJECT 2, reply to something I never sent | `reply_to_unsent_message` | `needs history` |
| ATTACHMENTS 1, unexpected attachment, or one that makes no sense | `attachment_from_unseen_sender`, `attachment_out_of_place` | `needs history`; the "makes no sense" half is `not computable` |
| ATTACHMENTS 2, possibly dangerous file type | `attachment_present`, `attachment_high_risk_type` | `computable` |
| CONTENT 1, click or open to avoid harm or gain something | `click_or_open_request`, `threat_of_consequence`, `too_good_to_be_true_offer` | `computable` |
| CONTENT 2, out of the ordinary, bad grammar or spelling | `spelling_errors`, `grammar_errors`, `odd_or_illogical_request` | `computable` for spelling; otherwise `not computable` |
| CONTENT 3, click or open request that seems odd or illogical | `click_or_open_request`, `odd_or_illogical_request` | `computable` for the request; "odd" is `not computable` |
| CONTENT 4, uncomfortable gut feeling | `gut_feeling` | `not computable` |
| CONTENT 5, compromising or embarrassing picture | `compromising_picture_lure` | `computable` |

### 6.3 CISA

| Document | Sign | Entries |
|---|---|---|
| CISA-RRP | "Recognize" item 1, urgent or emotional language, dire consequences | `urgency`, `threat_of_consequence` |
| CISA-RRP | "Recognize" item 2, requests for personal and financial information | `request_sensitive_information` |
| CISA-RRP | "Recognize" item 3, untrusted shortened URLs | `link_shortened_url` |
| CISA-RRP | "Recognize" item 4, incorrect addresses or links | `domain_lookalike_misspelling` |
| CISA-RRP | paragraph under the list, poor grammar or misspellings | `spelling_errors`, `grammar_errors` |
| CISA-RRP | "Resist", too good to be true | `too_good_to_be_true_offer` |
| CISA-RRP | "Omar" story | `display_name_address_mismatch`, `mimics_business_process`, `account_problem_claim`, `urgency`, `link_to_fake_login_page` |
| CISA-TIP | signs 1 to 6 | `urgency`, `request_sensitive_information`, `attachment_from_unseen_sender`, `link_shortened_url`, `display_name_address_mismatch`, `spelling_errors` |
| CISA-ASE | indicator 1, suspicious sender's address | `domain_lookalike_misspelling` |
| CISA-ASE | indicator 2, generic greetings and signature | `generic_greeting`, `missing_signer_details` |
| CISA-ASE | indicator 3, spoofed hyperlinks and websites | `link_text_target_mismatch`, `domain_lookalike_misspelling`, `domain_lookalike_suffix_swap`, `link_shortened_url` |
| CISA-ASE | indicator 4, spelling and layout | `spelling_errors`, `grammar_errors`, `unprofessional_design` |
| CISA-ASE | indicator 5, suspicious attachments | `attachment_from_unseen_sender`, `click_or_open_request`, `urgency` |
| CISA-ASE | "What is a phishing attack?" | `poses_as_trusted_party`, `request_sensitive_information`, `account_problem_claim`, `humanitarian_appeal`, `current_event_theme` |
| CISA-TEA | step 1, strange or unexpected requests, urgent language | `odd_or_illogical_request`, `urgency` |
| CISA-TEA | step 1, known contacts whose accounts were compromised | `known_sender_out_of_character` |
| CISA-TEA | step 1, personal or company-specific details | note under `generic_greeting` |
| CISA-GUIDE | p. 4, impersonation to obtain login credentials | `poses_as_trusted_party`, `authority_role_sender_name`, `request_sensitive_information` |
| CISA-GUIDE | p. 4, link to an imitation login portal | `link_to_fake_login_page` |
| CISA-GUIDE | p. 5, attachments with macro scripts; p. 8, macros | `attachment_with_macros` |
| CISA-GUIDE | p. 5, links that download executables | `link_target_high_risk_file` |
| CISA-GUIDE | p. 6, SPF, DKIM and DMARC | `sender_authentication_failure` |
| CISA-GUIDE | pp. 7 and 9, file extensions | `attachment_high_risk_type` |
| CISA-GUIDE | p. 7, mislabeled file extensions | `attachment_mislabeled_type` |

CISA-TEA step 1 also names "suspicious links" without saying what makes a
link suspicious, and its tip box says to hover over a link to see where it
leads. Neither states a cue of its own. The rest of CISA-GUIDE is advice for
network defenders and software makers, not cues a reader could see in a mail.

### 6.4 FTC

| Item | Entries |
|---|---|
| List item 1, suspicious activity or log-in attempts | `account_problem_claim` |
| List item 2, problem with account or payment information | `account_problem_claim` |
| List item 3, confirm personal or financial information | `request_sensitive_information` |
| List item 4, an invoice you do not recognize | `mimics_business_process` |
| List item 5, click a link to make a payment | `request_payment` |
| List items 6 and 7, government refund, coupon for free stuff | `too_good_to_be_true_offer` |
| Example sign 1, generic greeting | `generic_greeting` |
| Example sign 2, account on hold for a billing problem | `account_problem_claim` |
| Example sign 3, link to update payment details | `request_payment` |
| Intro, an unexpected message that looks like it is from a known company | `poses_as_trusted_party` |

## 7. Open questions for review

Classifications that could reasonably go the other way:

- `spelling_errors`: decidable only with a word list per language, and two
  CISA documents say the sign is fading.
- `missing_signer_details` and `signature_name_differs_from_sender`: both
  depend on finding the sign-off in a plain-text body.
- `recipients_unusual_mix`: "unusual" is a judgment. Only the two shapes
  KnowBe4 names are proposed, and the alphabetical one only approximately.
- `recipients_unknown_to_user` and `reply_to_unsent_message`: the seen-sender
  set stands in for something the daemon does not have (the people the reader
  knows, the reader's sent mail). Either could be called `not computable`.
- `sent_at_unusual_hour`: `not computable` only because the observation has no
  send time. If a sensor could supply one, the "odd hour" half would become
  decidable; the "unusual for this sender" half would still need a baseline.
- `link_target_high_risk_file`: a narrow reading of one sentence in
  CISA-GUIDE.
- `external_sender_unrelated_to_job`: classified by its judgment half. The
  external-sender half is decidable but says little in a personal mailbox.

Thin sourcing:

- `domain_lookalike_embedded` and `brand_name_in_freemail_sender` rest on
  examples in one blog post, without a stated rule.
- `authority_role_sender_name` is a fragment of a NIST cue, taken from what
  NIST marks in its sample email.
- 17 of the 37 decidable entries are stated by one publisher only (section 5
  shows which).

Cues expected to be common in honest mail, where only measurement can say
whether they carry any signal, and with which sign: `link_text_hides_url`,
`attachment_present`, `legal_boilerplate`, `security_indicator_text`,
`mimics_business_process`, `click_or_open_request`,
`authority_role_sender_name`.

Lists the sources do not supply: URL-shortener hosts, a fuller set of
high-risk attachment extensions, macro-capable file types, and nearly all of
every phrase list.
