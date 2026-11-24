# OT Incident Response Playbook: Unauthorized Modbus Write to a PLC

**Scenario:** a Modbus/TCP write command reaches a PLC from a source that is not
an authorized HMI or engineering workstation. Detected by Suricata behavioral
rules (sid 1000010 / 1000011) and raised in Wazuh (rule 100200).

**Scope:** GRFICSv3 simulated plant lab (OpenPLC, ScadaLTS HMI, Kali attacker).
The same structure maps to a production OT environment.

**Frameworks:** NIST SP 800-61 incident lifecycle, IEC 62443 zones/conduits,
MITRE ATT&CK for ICS (T0836 Modify Parameter / unauthorized command message;
related T0855 Unauthorized Command Message).

---

## Guiding principle (OT first)

The process stays running and safe. In OT, availability and safety outrank
confidentiality. No response step may risk tripping the live process. Automated
actions are limited to safe tasks; anything disruptive requires human approval
and is applied at the IT/DMZ boundary, never inside the control network or on the
controller.

---

## 1. Preparation

- Baseline of normal Modbus sources established (HMI, EWS) and encoded in the
  Suricata allowlist and the SOAR script's `ALLOWLIST`.
- Asset inventory of control-system hosts and the PLC.
- Detection in place: Suricata signature-to-behavioral rules, Wazuh SIEM
  ingestion of `eve.json`, Wazuh elevation rule 100200.
- SOAR playbook (`ot_soar_response.py`) installed and tested.
- On-call notification path configured (webhook).

## 2. Detection and analysis

1. **Alert fires.** Wazuh rule 100200 triggers on the Suricata OT signature.
   The SOAR playbook runs automatically and opens a case.
2. **Confirm it is real, not a false positive.** Check the source against the
   control-system inventory:
   - Source is a known HMI/EWS -> a trusted host is acting out of profile.
     Treat as possible compromise or misuse of a legitimate host.
   - Source is unknown -> rogue/unauthorized host on the control network.
     Higher severity.
3. **Characterize the command.** What register/coil was written, and to what
   value? Does the value push the process toward an unsafe state, or is it
   benign? Pull the full packet detail from Suricata and the Wazuh alert.
4. **Scope.** One write or a sequence? One PLC or several? Any correlated
   activity (scans, new sessions, logons) around the same time?
5. **Severity.**
   - CRITICAL: unknown source, or a write that moves the process toward unsafe.
   - HIGH: known host acting abnormally, benign value.

## 3. Containment (approval-gated, OT-safe)

Containment must not disrupt the process. Options, in order of preference:

1. **Increase monitoring** on the source and the target PLC. Always safe.
2. **Notify operations** so an operator watches the affected process and is ready
   to intervene by normal control means if a value drifts.
3. **Isolate the source at the IT/DMZ boundary (Purdue Level 3.5)**, not inside
   the control network. This requires analyst approval. The SOAR playbook stages
   this as a recommendation; it does not execute it.
4. **Never** auto-block a control host, drop traffic inside the control network,
   or take action on the PLC. Those can trip the process.

Document who approved any disruptive action and when.

## 4. Eradication

- If a legitimate host was compromised, remove the foothold (through normal
  change control, coordinated with operations, during a safe window).
- If a rogue device was connected, physically locate and remove it.
- Verify the PLC logic and setpoints are unchanged from the known-good baseline;
  restore from a trusted baseline if they were altered (change-controlled).

## 5. Recovery

- Confirm the process is in a known-good, safe state with operations.
- Restore normal monitoring thresholds.
- Confirm only authorized sources are communicating with the PLC again.

## 6. Post-incident

- Write up the timeline, impact, and root cause.
- Tune detections if the event revealed a gap or a false-positive source.
- Update the asset allowlist if the inventory changed.
- Capture lessons learned and feed them back into Preparation.

---

## Roles

| Role | Responsibility |
| --- | --- |
| SOC analyst | Triage the case, confirm/deny, drive the response, request approvals |
| SOC lead | Approve disruptive containment, coordinate across teams |
| Operations | Watch the affected process, intervene by control means if needed |
| OT/network engineering | Apply approved boundary controls, locate rogue devices |

## What the SOAR automation does vs what a human does

| Step | Automated (SOAR) | Human |
| --- | --- | --- |
| Open case | Yes | - |
| Enrich source (known vs unknown) | Yes | - |
| Notify on-call | Yes | - |
| Audit log | Yes | - |
| Decide severity beyond first pass | Assists | Yes |
| Approve disruptive containment | No | Yes |
| Act on the control network or PLC | Never | Yes, by control means |
