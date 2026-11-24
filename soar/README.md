# OT SOAR: automated, OT-safe response to unauthorized PLC writes

An end-to-end detection and response pipeline built on the lab. A behavioral
Suricata rule catches an unauthorized Modbus write to a PLC, Wazuh promotes it to
a high-severity alert, and a Python SOAR playbook triages it, opens an incident
case, and stages containment for a human to approve. The automation is built so
it can never disrupt the running process.

## The problem this solves

In OT, availability and safety come before confidentiality. You cannot let an
automated response take an action that might trip a live process. That rules out
the usual IT reflex of auto-blocking or auto-isolating. The goal here was to
automate the slow parts of incident response, detection, triage, enrichment, and
evidence, while leaving every process-affecting decision to a human.

## Architecture

Two network segments with a router between them, which is the segmentation model
real utilities use:

- Control network `192.168.95.0/24`: the PLC, engineering workstation, and
  process simulation
- Corporate network `192.168.90.0/24`: the HMI, the attacker, and adversary
  emulation

```
  Kali (corporate 192.168.90.6)
        |
        |  unauthorized Modbus/TCP write
        v
  OpenPLC (control 192.168.95.2:502)
        |
        |  seen on the control-network tap
        v
  Suricata  ->  behavioral rule (sid 1000010 / 1000011)  ->  eve.json
        |
        |  Wazuh agent forwards
        v
  Wazuh manager  ->  rule 100200 (level 12)
        |
        |  active response (runs on the agent nearest the OT)
        v
  ot_soar_response.py
        - classifies the source against an asset allowlist
        - sets severity: CRITICAL (unknown source) or HIGH (known host out of profile)
        - opens an incident case (JSON evidence)
        - notifies on-call (webhook)
        - stages containment for ANALYST APPROVAL, never auto-acting on OT
```

## The design decision that matters

The playbook does only safe things on its own: open a case, enrich it, notify,
log. It never blocks, never drops traffic inside the control network, and never
touches the PLC. When containment is warranted, it writes a recommendation to
block the source at the IT/DMZ boundary (Purdue Level 3.5) and marks the case
`OPEN_PENDING_ANALYST_APPROVAL`. A person decides.

That is the whole point. An automated response that can halt a running plant is
worse than the attack it is responding to.

## What it produces

One unauthorized write generates a case like this, automatically, seconds after
the event:

```json
{
  "case_id": "20261124T025203-192_168_90_6",
  "status": "OPEN_PENDING_ANALYST_APPROVAL",
  "detection": {
    "source_ip": "192.168.90.6",
    "source_assessment": "192.168.90.6 (NOT in control-system inventory)",
    "target": "OpenPLC controller (Modbus/TCP 502)",
    "suricata_signature": "OT ANOMALY Modbus write to PLC from non-engineering host",
    "suricata_sid": "1000011",
    "wazuh_rule": "100200"
  },
  "triage": {
    "classification": "unknown_source_write",
    "severity": "CRITICAL",
    "mitre_attack_ics": "T0836 Modify Parameter / unauthorized command message"
  },
  "response": {
    "recommended_action_pending_approval": "Block 192.168.90.6 at the IT/DMZ boundary firewall (Level 3.5), NOT inside the control network, and NOT on the PLC. ANALYST APPROVAL REQUIRED.",
    "ot_safety_note": "No automated action touched the PLC, the control network, or the running process."
  }
}
```

## Files

| File | What it is |
| --- | --- |
| `ot_soar_response.py` | The SOAR playbook. Runs as a Wazuh active response. Standard library only. |
| `local_rules.xml` | Wazuh rule 100200, elevates the Suricata detections and triggers the playbook. |
| `active-response.conf` | The manager's command and active-response wiring. |
| `wazuh-active-response-setup.md` | Full deployment steps across the agent and manager. |
| `ir-playbook-unauthorized-modbus-write.md` | The incident response playbook, mapped to NIST SP 800-61, IEC 62443, and MITRE ATT&CK for ICS. |

## Detection logic

The playbook holds an allowlist of hosts that are legitimately allowed to write
to the PLC (the HMI and the engineering workstation). The severity decision is
simple and defensible:

- Write from an allowlisted host: a trusted device acting out of profile. HIGH.
  Investigate the host, do not block it.
- Write from anything else: an unknown or rogue source on the control network.
  CRITICAL. Recommend a boundary block, pending approval.

## Notes from building it

A few things that are easy to get wrong and worth writing down:

- Suricata's `signature_id` decodes in Wazuh as `alert.signature_id`, not
  `data.alert.signature_id`. The Ruleset Test tool shows the real decoded field
  names.
- Wazuh field matching defaults to OS_Regex, which does not support `[..]`
  character classes. Matching `^100001[01]$` needs `type="pcre2"`.
- Wazuh ships the Enterprise ATT&CK database, so ICS technique IDs like T0836 are
  not in it. The ICS mapping belongs in the playbook's case output, not the
  Wazuh rule.
- Rule and config changes only take effect after a manager restart.
