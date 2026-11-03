# Attack: Unauthorized Modbus Write

## Summary
From the Kali attacker in the DMZ (192.168.90.6), sent an unauthenticated
Modbus write to the PLC (192.168.95.2) across the router. Modbus/TCP has no
authentication, so the PLC accepted the command as legitimate.

## Steps
1. Confirmed PLC Modbus port reachable from the DMZ: `nmap -p 502 192.168.95.2` -> open
2. Wrote value 60000 to holding register 1 using pymodbus (function code 6)
3. Read back the register to confirm the change took effect

## MITRE ATT&CK for ICS
- T0855 Unauthorized Command Message
- T0836 Modify Parameter

## Traffic signature
Normal: PLC (.2) <-> I/O (.10-.15) using func 4 (read) and 16 (write-multiple);
HMI reads with func 1/3/4.
Attack: 192.168.90.6 (DMZ) -> 192.168.95.2 func 6 (write single register).
No legitimate DMZ host ever writes to the PLC.

## Detection ideas
1. Alert on Modbus write (func 6/16) sourced from the DMZ.
2. Alert on any Modbus from a host that is not the PLC or known I/O.
3. Alert on writes to the PLC from anything other than the engineering workstation.
