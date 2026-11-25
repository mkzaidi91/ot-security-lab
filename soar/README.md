# OT SOAR: automated, OT-safe response to unauthorized PLC writes

This is the response half of the lab. The detection side catches an unauthorized
Modbus write to the PLC. This part is what happens next. A Wazuh rule promotes
that alert to high severity and runs a Python playbook I wrote. The playbook
triages the alert, opens an incident case, and recommends containment, but it
leaves anything that could touch the process to a human. That constraint drove
the whole design.

## Why it works this way

In OT, availability and safety come before confidentiality. A wrong automated
action, like blocking a host that turns out to be legitimate or isolating a
segment mid-operation, can do more damage than the attack. So I did not want the
automation making those calls. I wanted it to do the slow, safe work for me
(enrich the alert, classify the source, open a case, page on-call) and hand a
person a clear recommendation to approve or reject.

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

## What the playbook will and won't do

On its own the playbook only does safe things: open a case, enrich it, send a
notification, write a log. It never blocks traffic, never touches the control
network, and never talks to the PLC. When it thinks the source should be
contained, it writes that as a recommendation (block at the IT/DMZ boundary,
Purdue Level 3.5) and marks the case `OPEN_PENDING_ANALYST_APPROVAL`. Someone has
to approve it before anything happens.

I built it that way on purpose. On the IT side you might auto-isolate a
compromised host and move on. On a plant floor that same reflex can trip a
running process, so the automation stops at the boundary and a human makes the
call.

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

The detection-to-case chain looked simple on paper and then did not fire, and
chasing down why was most of the work. Keeping the notes here because they are
the useful part.

- **My Wazuh rule matched nothing at first.** The rule chains off the built-in
  Suricata alert (86601) and matches on the signature ID, but it kept stopping at
  86601 and never elevated. I ran a real alert through the Ruleset Test tool and
  the decoded fields showed the ID as `alert.signature_id`, not the
  `data.alert.signature_id` I had written. One wrong prefix, silent failure.
- **Then it still would not match.** Wazuh's default field matching is its own
  regex flavor (OS_Regex), which does not understand `[..]` character classes, so
  `^100001[01]$` was being read literally. Adding `type="pcre2"` to the field
  fixed it.
- **The MITRE tag threw a warning.** Wazuh ships the Enterprise ATT&CK database,
  and T0836 is an ATT&CK for ICS technique, so it is not in there. I dropped the
  MITRE block from the rule and kept the ICS mapping where it belongs, in the
  playbook's case output.
- **Nothing takes effect until you restart the manager.** I lost time testing
  edits that were saved but not loaded. Rule and config changes need a manager
  restart first.
