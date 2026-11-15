# Code Red Freight — CSCTF-style Writeup

> Points: forensic / mail-compromise DFIR
>
> **Flag format:** `CSCTF{<device_name>_<rule_name>_<download_count>}`
>
> **Flag:** `CSCTF{REDACTED}`

---

### Overview

#### Challenge Brief
Tarnovel Rail Freight's defence-consignment manifests are reaching an outside mailbox.
The dispatcher noticed nothing. You have her identity, mailbox-audit exports, and the
email she clicked. Identify the device the adversary controls, the rule leaking
manifests, and the number of files they downloaded.

*(Constructed incident built from sanitized Microsoft Entra ID / Purview-style exports.
Work only with the supplied evidence — no live probing of any named domains/addresses.)*

#### Resources

- `lure/email_phish.png` — the lure email ("Jordan Smith" shared `Draft_Budget_v2.docx`)
- `lure/devicecode_phish.png` — fake "Verify it's you" page with device-login code
- `logs/InteractiveSignIns_2026-10-28_2026-10-29.csv`
- `logs/NonInteractiveSignIns_2026-10-28_2026-10-29.csv`
- `logs/AuditLogs_2026-10-29-Patti_Fernandez.csv`
- `logs/UnifiedAuditLog_Patti.csv`

---

### Solution Walkthrough

#### 1. Read the lure
`email_phish.png`: an external-sender message from `ragubarden@proton.me` ("Jordan
Smith") sharing an OneDrive doc, "Review Document" → `https://5sharepoint.cz/...`.
The landing page (`devicecode_phish.png`) is a classic **device-code phishing**
page: instructions to visit `microsoft.com/devicelogin` and enter code `CXR7QK2WD`
so the victim "unlocks" the file — while the attacker harvests the token issued
against her tenant.

#### 2. Segregate attacker vs. dispatcher infrastructure in the sign-ins
Interactive/near-real-time sign-in logs split cleanly by IP:

| Actor | IP | Geo | Devices/Apps |
|---|---|---|---|
| Legit dispatcher (Patti) | `198.51.100.24` | Romania (Timisoara/Bucuresti) | `R3M0TE-W0RK-PC`, normal OWA/Teams day |
| Adversary | `203.0.113.77` | Montreal, Quebec, CA | device `95caec44-c8af-4786-976c-73bd33d9d143` |

Smoking gun in the interactive log:

```
2026-10-29T15:04:55Z  Microsoft Authentication Broker  203.0.113.77
                      Status: Success
                      Authentication Protocol: deviceCode     <-- device-code phish
30s earlier: "For security reasons, user confirmation is required..." (the failed pull)
```

#### 3. Name the adversary's device (Entra audit log)
`AuditLogs_2026-10-29-Patti_Fernandez.csv` — `Device Registration Service / Register device`,
15:05:03, source IP `203.0.113.77`, Device Id `95caec44-c8af-4786-976c-73bd33d9d143`
(matching every attacker-IP sign-in):

```
Target1DisplayName = D3VC0DE-R3L4Y          <-- adversary-controlled device
D2: Device Profile = RegisteredDevice
D3: Device Trust Type = Azure AD join
```

(Benign counterweight: the 10-28 registration `R3M0TE-W0RK-PC` from Romania.)

#### 4. Find the leaking rule (Unified audit log)
`UnifiedAuditLog_Patti.csv` contains two `New-InboxRule` records. The 10-28 one
("Newsletters", FromAddressContainsWords: newsletter/digest/noreply → MoveToFolder)
is a normal Filter rule from the legit IP. The one that matters:

```
2026-10-29T15:28:57  New-InboxRule
  ClientIP : 203.0.113.77:17091
  DeviceId : 95caec44-c8af-4786-976c-73bd33d9d143        <-- attacker's session
  Parameters:
    Name              = M4N1F3ST-L3AK                    <-- the leaking rule
    ForwardTo         = ragubarden@proton.me             <-- the outside mailbox
    StopProcessingRules = True
    AlwaysDeleteOutlookRulesBlob = False
```

Exactly the BEC playbook: hidden-ish name, forwards to the lure's sender address —
defence-consignment manifests piped straight to the adversary.

#### 5. Count the downloads
`FileDownloaded` events (RecordType 6), all from `ClientIP = 203.0.113.77` via
Microsoft Teams — four of them between 15:20 and 15:21, **4** files:

1. `Investor Relations Meeting Presentation.pptx` (OneDrive)
2. `Notes.docx` (OneDrive)
3. `aerialshot.jpg` (Mark8ProjectTeam site)
4. `Local Resource Guide.docx` (benefits site)

No other `FileDownloaded` records exist in the export, and none at all during her
legitimate session, so the downloaded count is **4**.

---

### Answer

- **Adversary's device:** `D3VC0DE-R3L4Y` (`95caec44-c8af-4786-976c-73bd33d9d143`, IP `203.0.113.77`)
- **Leaking Inbox rule:** `M4N1F3ST-L3AK` → `ragubarden@proton.me`
- **Files downloaded:** `4`

**Flag:** `CSCTF{REDACTED}`

---

### MITRE-style chain (for the report)

1. **T1566.002 / T1656** — lure: shared-document phish → device-code login page
   (`5sharepoint.cz`, code `CXR7QK2WD`)
2. **T1528 / T1621** — token harvested via `microsoft.com/devicelogin` (deviceCode
   grant success 15:04:55Z)
3. **T1098.004** — persistence in the mailbox: Inbox rule `M4N1F3ST-L3AK`
   (ForwardTo external, StopProcessingRules) 15:28:57Z
4. **T1213.002** — exfiltration: 4 SharePoint/OneDrive files downloaded 15:20–15:21Z;
   automated manifest forwarding via the rule
