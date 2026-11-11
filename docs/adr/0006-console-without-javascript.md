# 0006: Admin console without JavaScript

## Decision

The admin console is server-rendered HTML with plain forms and no JavaScript at all. The
original design called for HTMX. Two related deviations are recorded here as well.

## Why no JavaScript

- The Content-Security-Policy can be `default-src 'none'` with only same-origin styles, images
  and form posts. Script injection has nothing to run, and there is no vendored script to keep
  patched.
- Nothing in the console needs client-side behaviour: every action is a form post followed by
  a redirect or a re-rendered page.

## Related decisions

- **Login asks for tenant, e-mail and password**, then a TOTP code. E-mail addresses are
  unique per tenant, and knowing the tenant lets every lookup run under ordinary row-level
  security.
- **Sessions** are random values in `__Host-` cookies; the database stores only their SHA-256.
  Session lookup happens before the tenant is known, through a select-only row-level-security
  policy on the presented hash.
- **The login form's CSRF token** is an unsigned double-submit token in a `__Host-` cookie.
  The prefix prevents other origins and subdomains from setting it, so signing adds nothing.
- **The playground** acts through a selected API key's scopes and policies, but the audit
  entry names the console user and records the key as `via_key`.
- **Layering**: the design said the console would not touch database models directly. The
  console's read-only page queries do use models directly, inside tenant-scoped sessions.
  Changes to keys, policies and encryption go through the same audited service functions as
  the API and CLI. Sign-in attempts are audited; session creation and sign-out are not.

## Cost

- Full page loads; no live progress for long operations such as re-encryption.
- Lockout (five failures, 15 minutes) lets anyone who knows a tenant and e-mail keep an
  account locked. Operators recover it with `securedb unlock-user`.
- Console errors such as "owners only" are returned as JSON problem documents, not styled
  pages.
