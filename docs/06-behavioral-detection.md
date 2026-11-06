# Behavioral Detection: catching reconnaissance

## Why
The Suricata signature rules (docs/04) catch a Modbus *write* by its function
code. But a subtler attacker could sit on an already-reachable host and just
*read* the controller first, reconnaissance that a function-code signature
never sees. This adds a behavioral layer.

## The rule (allowlist / anomaly)
On this plant, the only hosts that should ever initiate Modbus to the PLC
(192.168.95.2:502) are the HMI and the engineering workstation. Anything else
touching the PLC over Modbus, even a read, is anomalous:

A second rule flags a Modbus write from any host that is not the engineering
workstation (sid:1000011).

## Proof it works
Ran a READ-ONLY Modbus request from Kali (192.168.90.6, DMZ). Result:
- Behavioral rule 1000010 fired (unrecognized host talking to the PLC).
- The write-signature rules (1000001, 1000003) stayed silent, because nothing
  was written.

This shows the behavioral layer detects reconnaissance the signature rules miss.

## MITRE ATT&CK for ICS
- T0846 Remote System Discovery (recon reads)
- T0836 Modify Parameter (the write variant, sid:1000011)

## Takeaway
Signature detections catch known-bad actions; behavioral detections catch
anomalies against a known-good baseline. A real OT monitoring program needs
both. The next step would be tuning against a live plant baseline and adding
time-aware rules (e.g. a write outside an approved maintenance window).
