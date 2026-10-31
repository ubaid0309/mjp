# ByteMart secure reference (DEMO DATA)

Fixed counterparts of the main files in `../bytemart-vulnerable/`, used to show what remediation looks like and,
in Phase 2, as patched input for verification re-scans.

Scanning these files with the SecureMatrix bundled rules reports one remaining result:
`shop/app.py` `/preview` is still flagged as possible SSRF. The code validates the scheme, host allow-list and
resolved IP before fetching, but a taint rule cannot see that `abort(400)` guards the request. This is a known
false positive of static analysis; in SecureMatrix it should be reviewed and closed as **Accepted risk** with
that justification.
