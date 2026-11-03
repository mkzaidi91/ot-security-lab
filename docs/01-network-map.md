# Network Map

## ICS network (192.168.95.0/24) — Purdue Levels 1-2
| Device | IP | Role |
| --- | --- | --- |
| simulation | 192.168.95.45 | Physical process |
| plc | 192.168.95.2 | OpenPLC controller |
| EWS | 192.168.95.5 | Engineering workstation |

## DMZ network (192.168.90.0/24) — Purdue Level 3.5
| Device | IP | Role |
| --- | --- | --- |
| HMI | 192.168.90.107 | Operator interface (Scada-LTS) |
| kali | 192.168.90.6 | Attacker |
| caldera | 192.168.90.250 | Attack automation |

## Router
- ICS side: 192.168.95.200
- DMZ side: 192.168.90.200
- Firewall between the two zones; all cross-zone traffic passes through it.

## Key observation
The PLC (192.168.95.2) controls the process over Modbus/TCP.
The attacker starts in the DMZ and must cross the router to reach the
ICS network — the crossing point where detection matters most.
