# OT Security Lab: ICS Attack & Detection

Hands-on industrial control system (ICS) security lab built on
[GRFICSv3](https://github.com/Fortiphyd/GRFICSv3) by Fortiphyd Logic,
running in Docker on a Proxmox VM. This project simulates a chemical
plant, carries out a Modbus attack against the PLC, detects it with a
Suricata rule mapped to MITRE ATT&CK for ICS, and centralizes the
alert in a Wazuh SIEM.

## What this demonstrates
- Mapping an OT network across ICS and DMZ zones (Purdue model)
- Baselining normal Modbus/TCP traffic
- Executing an unauthenticated Modbus write against a live PLC
- Observing physical process impact in the operator HMI
- Writing a network detection and confirming it fires on the attack
- Forwarding the detection into a SIEM, as a real OT SOC would

## Lab environment
- Host: Proxmox VE, Ubuntu 24.04 VM (4 vCPU, 12 GB RAM)
- GRFICSv3 containers: simulation, PLC (OpenPLC), HMI (Scada-LTS),
  engineering workstation, router, Kali attacker, Caldera
- Change from upstream: macvlan parent set to the VM's NIC (ens18)
- Detection: Suricata 7 on the ICS network; alerts shipped by a Wazuh
  agent to a central Wazuh manager

## The target process
The lab models the Tennessee Eastman chemical process. The PLC controls
feed, purge, and product valves to hold reactor pressure in a safe range.

![OpenPLC dashboard](screenshots/openplc-dashboard.png)

## The attack
From the Kali attacker in the DMZ (192.168.90.6), an unauthenticated
Modbus write (function code 6) was sent to the PLC (192.168.95.2) across
the router. Modbus/TCP has no authentication, so the PLC accepted it as
legitimate. Maps to MITRE ATT&CK for ICS **T0855 (Unauthorized Command
Message)** and **T0836 (Modify Parameter)**.

Operator HMI — valves under automatic control:

![HMI normal](screenshots/hmi-normal.png)

Operator HMI — purge valve forced to 0% by the unauthorized write:

![HMI under attack](screenshots/hmi-attack.png)

## The detection
A Suricata rule monitors the ICS network for Modbus write function codes
directed at the PLC, flagging writes sourced from the DMZ. On the live
attack it fired immediately:

See [`detections/ot-modbus.rules`](detections/ot-modbus.rules).

## SIEM integration (Wazuh)
A Wazuh agent on the OT lab VM ships the Suricata alerts to a central
Wazuh manager, which decodes them and raises SIEM alerts.

Both OT attack alerts in the Wazuh dashboard (agent: ot-lab, rule 86601):

![Wazuh dashboard](screenshots/wazuh_dashboard.jpg)

Alert detail — source IP and MITRE mapping:

![Wazuh alert detail 1](screenshots/wazuh_detection1_details.jpg)

![Wazuh alert detail 2](screenshots/wazuh_detection2_details.jpg)

Full pipeline: Kali (DMZ) -> PLC -> Suricata (ICS sensor) -> Wazuh agent
-> Wazuh SIEM, tagged with MITRE ATT&CK for ICS T0836 and T0855.

## Documentation
- [01 Network map](docs/01-network-map.md)
- [02 Traffic baseline](docs/02-traffic-baseline.md)
- [03 Attack](docs/03-attack.md)
- [04 Detection](docs/04-detection.md)
- [05 SIEM integration](docs/05-siem-integration.md)

## Credits
Built on [GRFICSv3](https://github.com/Fortiphyd/GRFICSv3) by Fortiphyd
Logic. Simulation and container images are their work.

## Behavioral detection (catching reconnaissance)
The Suricata signature rules above catch a Modbus *write* by its function code.
To catch a subtler attacker, I added a behavioral rule: on this plant only the
HMI and the engineering workstation should ever initiate Modbus to the PLC, so
anything else touching it — even a read — is flagged as an anomaly.

Tested with a **read-only** recon from the DMZ attacker: the behavioral rule
(sid 1000010) fired, while the write-signature rules stayed silent — proving the
behavioral layer catches reconnaissance the signatures miss. See
[`docs/06-behavioral-detection.md`](docs/06-behavioral-detection.md).

## Notes & gotchas (things I hit building this)
A few real problems I worked through, kept here because they're the useful part:

- **GRFICS networking wouldn't come up on the VM.** The compose file defines
  macvlan networks with a parent of `eth0`, but on my Ubuntu VM under Proxmox
  the NIC is `ens18`, so the networks failed to create until I pointed the
  macvlan parent at the right interface.
- **Reading the Modbus function code in Suricata.** The function code is the
  8th byte of the Modbus/TCP payload, so the rules match on `content:"|06|";
  offset:7; depth:1` (06 = write single register, 10 = write multiple). Getting
  the offset right was the difference between the rule firing and silently not.
- **Duplicate-rule parse failure.** When I was iterating I appended the same
  behavioral rules twice; Suricata loaded the first copy and threw a "duplicate
  signature" error on the second. Deduping the rules file fixed it.
- **Wazuh agent version mismatch.** The manager runs in the single-node Docker
  compose at v4.14.7, so the agent had to match — a mismatched agent version
  wouldn't report cleanly.
- **Reaching the Wazuh dashboard remotely.** The dashboard sits behind a
  subnet-routed address and I couldn't hit it over Tailscale at first; I ended
  up running Tailscale directly on the Wazuh host to get a clean path to it.

## Why behavioral on top of signatures
The signature rule only sees a write. When I ran a read-only recon from the
attacker box, the write rules stayed silent but the behavioral rule caught it,
which is exactly the gap behavioral detection is for. That's the lesson I'd
carry into a real environment: signatures for known-bad, behavioral baselines
for everything else.
