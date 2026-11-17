# Gmail page structure fixtures

Captured 2026-11-12 from the repo owner's logged-in Gmail (web, Chrome,
English UI), in a tab opened for the purpose, and copied here byte for byte.
They are the only source of truth for the selectors in `ext/gmail.js`: do not
edit them, and do not add hand-written "Gmail-like" markup beside them. A case
that is missing here needs a new capture.

## Files

| File | What it is |
|---|---|
| `gmail-single-message-attachments.html` | a conversation with one expanded message and two attachments; all attribute names kept |
| `gmail-details-table.html` | the details table that appears inside `.gs` only after the "show details" control (`.ajy`) is clicked; seven rows |
| `gmail-thread-two-collapsed-one-expanded.html` | a three-message conversation: two collapsed messages, one expanded; noisy attribute names (`js*`, `aria-*`, `style`, `tabindex`, `id`, tooltips, hovercards) omitted |

## How they were made

The owner allowed the capture on one condition: only tag names, class names
and attribute names leave the page, never message text. A script walked
`div[role="main"]` of an opened conversation and kept every element matching a
list of candidate selectors, plus its ancestors. Everything else was dropped.

## Every value is a placeholder

- `class` values are real.
- Every other attribute is reduced to its name, except these, which carry
  placeholders so that selectors and attribute reads still work: `email` is
  `user@example.com`, `name` is `Sender Name`, `href` is
  `https://example.com/`, `download_url` is
  `application/pdf:file.pdf:https://example.com/file.pdf` (the real shape is
  `mime:filename:url`), and message and thread ids are `id1`, `id2`, ... with
  equal real ids mapped to the same placeholder.
- An element that had text of its own has the single character `x`.
- The message body (`.a3s`) is an empty element: nothing inside a message was
  read. A test that needs body content inserts a minimal constructed body at
  run time.
- `role="main"` on the root was put back by hand: the element was found with
  that selector. No other attribute value was read.

## What the capture confirmed in the live page

Counts on the single-message conversation:

| Selector | Count | Meaning |
|---|---|---|
| `h2.hP` (has `data-legacy-thread-id`, `data-thread-perm-id`) | 1 | subject |
| `.adn.ads[data-legacy-message-id][data-message-id]` | 1 | an expanded message |
| `span.gD[email][name]` | 1 | sender; read the attributes, the element has no text of its own here |
| `.hb span.g2[email][name]` | 1 | a recipient |
| `.ii.gt > .a3s` | 1 | message body |
| `.aQH > span.aZo[download_url]` | 2 | attachment cards; `span.aV3` inside holds the file name |
| `.ajy` (contains `img.ajz`) | 1 | the "show details" control |
| `.ajA`, `.ajC` before clicking `.ajy` | 0 | the details table is not in the page until asked for |

- **Reply-to is not available without a click.** It is a row of the details
  table, and only when the message has one.
- **Collapsed messages carry no id and no body.** They are `div.kv`
  containing `.adf.ads`, with `span.gD[email][name]` and a snippet
  `div.iA.g6`. Only the expanded message (`div.h7` containing `.adn.ads`) has
  `data-legacy-message-id` and `.a3s`.
- **Ids.** `data-message-id` is a separate value from the legacy id. In the
  single-message conversation the subject's `data-legacy-thread-id` equals the
  message's `data-legacy-message-id`; in the three-message one they differ.
- **Links in the body.** Of the two anchors in the captured body, neither
  `href` started with `https://www.google.com/url`; one carried a
  `data-saferedirecturl` attribute. The attribute names seen on body anchors
  were `href`, `value`, `target`, `data-saferedirecturl`. So the page keeps
  the original target in `href`.

## Not captured

A message with a reply-to, a message with inline images, a non-English UI, and
the "N older messages" stub in long conversations.
