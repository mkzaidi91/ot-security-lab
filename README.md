# OT Security Lab

Hands-on industrial control system (ICS) security lab built on
[GRFICSv3](https://github.com/Fortiphyd/GRFICSv3) by Fortiphyd Logic,
running in Docker on a Proxmox VM.

## Goals
- Map a simulated chemical plant network (PLC, HMI, engineering workstation)
- Baseline normal Modbus/TCP traffic
- Simulate attacks on the PLC (unauthorized Modbus writes)
- Build detections mapped to MITRE ATT&CK for ICS

## Lab environment
- Host: Proxmox VE, Ubuntu 24.04 VM (4 vCPU, 12 GB RAM)
- GRFICSv3 containers: simulation, PLC (OpenPLC), HMI (Scada-LTS),
  engineering workstation, router, Kali attacker, Caldera
- Change from upstream: macvlan parent set to the VM's NIC (ens18)

## Progress
- [x] Lab deployed
- [ ] Network map
- [ ] Traffic baseline
- [ ] Attack simulation
- [ ] Detection rules
