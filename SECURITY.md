# CORA security review

**Scope:** every file in `src/`, `views/` and `public/app.js`, plus the npm dependency tree.
**Date:** 2026-10-11 · **Version:** 0.3.1
**Method:** manual code review, then a probe to confirm each finding, then a fix with a regression test. The tests are in `test/security.test.js`, numbered SEC-01 to SEC-10.

## Findings and fixes

| ID | Severity | Finding | Fix |
|---|---|---|---|
| SEC-01 | **High** | **CSRF bypass.** The CSRF check skipped every `multipart/form-data` request, so another website could submit a hidden form to CORA. Confirmed: a cross-site multipart POST to `/data/reset-samples` with no token replaced all 13 evidence sources. Next-step requests were also open to this. Only POST was checked. | The token is required on every POST, PUT, PATCH and DELETE. The only exemption is the upload route, which checks the token itself after reading the file. Refusals return 403. |
| SEC-02 | **High** | **"Reload synthetic data" was always on.** Any user could overwrite real uploaded evidence with demo data. | Off by default. Only `npm run dev` or `CORA_ENABLE_SAMPLE_RESET=1` turns it on, and the button is hidden otherwise. |
| SEC-03 | **Medium** | **No authorisation or audit trail.** Every signed-in host user could change scoring settings and upload evidence that drives the risk ratings. Nothing recorded who did it. | New host hooks: `authorize(req, action)` for the actions `view`, `assess` and `manage`, and `currentUser(req)`. Without these hooks every signed-in user can do everything. The user is recorded on runs (`created_by`), uploads (`uploaded_by`), column mappings (`mapped_by`) and settings (`updated_by`). The Configure menu is hidden from users who may not manage. |
| SEC-04 | **Medium** | **Step lock bypass.** Posting "Next" for step 11 skipped straight to the end of a step-by-step run. A non-numeric step was saved into the database. | The step must be a whole number from 1 to 11, and no further than the analyst has reached. |
| SEC-05 | **Medium** | **Unchecked input.** Names such as `__proto__` or `constructor` reached `Object.prototype` and caused server errors; an upload under such a name wrote a stray file. Tier and tolerance accepted any number, including negatives. The extended form parser allowed nested objects. | Lookups use own keys only, and form fields are flat. Repeated fields count once. Tier must be 1 to 4 and the tolerance between 0 and 8,760 hours. Lists are limited to 500 items and 2,000 fields. |
| SEC-06 | **Low** | **Settings not range-checked.** Negative weights, percentages above 100, and free text as the risk appetite were accepted. Any of these could silently distort ratings. | Numbers must be from 0 to 100,000 and percentages 100 or less. The risk appetite must be Low, Medium, High or Critical. Text is limited to 500 characters. |
| SEC-07 | **Low** | **Missing protections.** The Content-Security-Policy had no `object-src`, `base-uri` or `form-action` limits. Result pages could be cached by the browser or a proxy. The Secure cookie flag was off unless set. | Policy tightened, cross-origin policies added, and `Cache-Control: no-store` set on every page and on the CSV export. The cookie is Secure by default when `NODE_ENV=production`, with a warning if it is turned off. |
| SEC-08 | **Low** | **Sessions never expired on the server.** A copied session cookie stayed valid indefinitely, because only the browser enforced its lifetime. | The issue time is signed into the cookie, and sessions older than 8 hours are rejected by the server. |
| SEC-09 | **Low** | **Weak secrets and upload handling.** Any secret key was accepted, even a few characters. Uploaded files were stored with default permissions. Upload requests had no limits on the number of fields or parts, and a too-large file gave a 500 error. | The secret key must be at least 32 characters. Evidence files are owner-only (0600, folders 0700). Upload requests are limited to 10 fields and 12 parts, and an oversized file returns 413. |
| SEC-10 | Info | **Spreadsheet formula injection in the risk CSV export.** This was already fixed in the Node port. | Regression test added. |

## Reviewed with no issue found

- **Output encoding:** Nunjucks escapes all output. The CSRF field is the only content marked safe, and it is a random base64url token. No user data appears in `href`, `src` or `hx-*` attributes or in scripts; inline style widths are computed numbers.
- **Database:** no request value reaches a MongoDB query as an operator. Ids are converted with `Number()` and source kinds are checked against a fixed list.
- **Files on disk:**
  - Upload names are reduced to `[A-Za-z0-9._-]` with a timestamp and hash prefix, so they cannot escape the upload folder.
  - Uploaded files are parsed but never served back to the browser.
  - Static files are served by `express.static`.
- **Client side:**
  - htmx 2.0.4 only sends requests to its own origin by default.
  - The CSP blocks inline scripts and `eval`.
  - `public/app.js` only empties the evidence drawer and does not insert content.
- **Errors:** the error handler logs the stack on the server and shows the user a generic message.
- **Dependencies:** `npm audit` reports 0 vulnerabilities (production and development).

## Remaining items for the host application

1. **Authentication** is the host's job. Mount CORA behind the host's login check and pass `authorize` and `currentUser` (see the README).
2. **HTTPS and HSTS:** set these at the reverse proxy or in the host application.
3. **Rate limiting:** an assessment run reads every source and takes about a second. Limit `POST /cora/run` and the upload route at the host or proxy.
4. **Encryption at rest:** uploaded evidence such as hostnames, IP addresses, vulnerabilities and owners is stored in `CORA_DATA_DIR`. Put that folder and MongoDB on encrypted storage and include both in backups.
5. **Log retention:** server logs may contain hostnames from failed uploads. Apply the bank's log handling policy.
6. **Inline styles:** the CSP allows `style-src 'unsafe-inline'` because templates set bar widths inline. This carries no script risk, but it can be removed later by moving the widths into CSS variables.
