# ByteMart (SecureMatrix demo project)

**DEMO DATA. INTENTIONALLY VULNERABLE. DO NOT DEPLOY.**

ByteMart is a small, fictional online shop written to exercise the SecureMatrix scanner. All credentials, keys and
users in it are synthetic. `AKIAIOSFODNN7EXAMPLE` is the example key ID from AWS's own documentation.

| Area | File | Intentional weakness |
|---|---|---|
| Python / Flask storefront | `shop/app.py` | SQL injection, reflected XSS, command injection, path traversal, SSRF, unrestricted upload, client-controlled admin check, debug mode |
| | `shop/security.py` | MD5 password hashing, DES encryption, predictable reset tokens, unverified JWT |
| | `shop/config.py`, `.env` | Hard-coded secret key and AWS key, plaintext DB password, DEBUG enabled |
| Node / Express API | `api/server.js` | SQL via template literal, NoSQL operator injection, command injection, open redirect, permissive CORS, cookie flags, `Math.random` tokens |
| | `api/public/app.js` | DOM XSS through `innerHTML` |
| PHP legacy pages | `legacy/profile.php` | Reflected XSS, SQL concatenation, local file inclusion, unsafe upload, `unserialize` |
| Java reports | `reports/.../ReportService.java` | Statement concatenation, MD5, DES, `Runtime.exec` |
| Container | `Dockerfile` | Runs as root |

`node_modules/` is included on purpose: SecureMatrix should exclude it (it contains an `eval` that must not be reported).
Secure versions of the main files are in `../bytemart-secure-reference/`. `../bytemart-vulnerable.zip` is this folder, ready to upload.
