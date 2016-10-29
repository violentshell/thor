# thor
#### Connection Destruction tool.
Thor is a program designed to inject RST's between two arbitrary machines, immediately tearing down the connection. It requires that the attacker/user machines must be able to see at least one side of the targeted traffic (span port/tap/source). It can be used to persistently deny IP's or Ports in place of an inline firewall with the use of the `-p` switch.

Thor can/will inject a packet when one of two conditions are met:

1. The connection has a 0.2 second gap in trasmistion, or
2. The inbuilt, 2 second, timer elapses. In this case thor will use the previous packets to guess a sequence number in range (TODO)
    
## Usage:
```
thor.py [-i Eth0] [-t 192.168.1.1] [-s 22] [-v v, vv] [-p]

Thor: Killing conns since 2016

optional arguments:
  -h, --help      show this help message and exit
  -i eth0         The interface to use
  -t 192.168.1.1  The target server.
  -s 22           The target port.
  -v v, vv        The verbosity level
  -p              Persistently kill connections
```
  
## Common usage examples:
  
#### Deny port 
  thor.py -s 22 -i eth0
  
#### Deny IP
  thor.py -t 192.168.1.1 -i eth0
  
#### Deny IP + Port persistently. Be verbose.
  thor.py -t 192.168.1.1 -s 22 -i eth0 -p -v vv

## Dependencies:
* Python 3.5
* Scapy 3.0.0
    
## Tested on:
* Windows 10
* Kali 2016.2

## Notes:
  * On windows, there is an option to choose from a list of interfaces because windows sucks at this.
  * Currently beta, please let me know if you have issues

  
