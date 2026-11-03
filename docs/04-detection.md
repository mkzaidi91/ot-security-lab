# Detection: Unauthorized Modbus Write

## Approach
Network-based detection with Suricata 7 monitoring the ICS network (ens18.95).
Rules alert on Modbus write function codes (6 = Write Single Register,
16 = Write Multiple Registers) directed at the PLC (192.168.95.2), and
specifically flag writes sourced from the DMZ (192.168.90.0/24).

## Why this works
Baseline traffic shows only the PLC and its I/O devices exchanging Modbus,
and the HMI performing reads. No legitimate DMZ host ever writes to the PLC,
so a write from the DMZ is a high-confidence indicator of attack.

## Result (fast.log)
Both rules fired on the live attack:
- 1:1000001 OT UNAUTHORIZED Modbus Write Single Register to PLC
- 1:1000003 OT CRITICAL Modbus write from DMZ to PLC
Source 192.168.90.6 (Kali, DMZ) -> 192.168.95.2:502 (PLC).

## MITRE ATT&CK for ICS
- T0855 Unauthorized Command Message
- T0836 Modify Parameter

## Next step
Forward Suricata eve.json / fast.log into Wazuh SIEM for centralized
alerting, correlating OT network detections with host logs.
