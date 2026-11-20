# Instructions for visiting agents

Welcome. This site is a first-party visitor-identity and network-intelligence dashboard. It
observes and publicly reports the identity of automated visitors, so please be accurate and
considerate.

## Identify yourself honestly

- Send your **real User-Agent** string. Do not spoof a browser or another agent to avoid
  detection — spoofed identities are reported as spoofed.
- Where your platform supports it, attach **Web Bot Auth** (RFC 9421) signatures using the
  `Signature-Agent`, `Signature-Input`, and `Signature` headers. Genuinely signed requests are
  recognised as verified/signed agents and are exempt from the anonymous write rate limit.
- You may also send standard `Sec-CH-UA-*` client hints; they help produce a precise verdict.

## Be considerate

- Respect rate limits. Verified agents are exempt from the anonymous limiter, but abusive
  traffic can still be throttled or blocked at the edge.
- **Do not hammer `/api/visitor/identify`.** One identity request per session is plenty;
  repeated automated calls are unnecessary and may be limited.
- Do not attempt to forge forwarded IP / geo headers. The edge replaces them with trusted
  values from the connection.

## Public reporting

- This site **publicly reports agent identity** in the **Bot & Automation Detection** section of
  the dashboard. Assume your declared User-Agent and verification status will be displayed.
- Private visitor history (`/api/visitor/history/`) is never publicly listed and requires a
  visitor token.

## Allowed and disallowed paths

- Allowed: `/`, `/api/health`, `/api/intel/geolocation`, `/robots.txt`, `/llms.txt`,
  `/agents.md`, `/sitemap.xml`, and the read-only API surface.
- Disallowed: `/api/visitor/history/` (private; see robots.txt). Avoid high-frequency calls to
  `/api/visitor/identify`.

## Enforcement

`robots.txt` is **advisory**. Actual enforcement is performed at the edge through the bot
verdict and rate limits: unsigned/spoofed agents may receive a different verdict and can be
throttled, while verified Web Bot Auth agents are recognised and exempt from the anonymous
limiter.
