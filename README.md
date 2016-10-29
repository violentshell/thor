# thor
## Connection Destruction tool.

Used to inject RST's between two arbitrary machines to immediately tear down the connection. Attacker/user machine must be able to see traffic (span port/tap/source). Can be used to persistently deny IP or Ports in place of an inline firewall.

### Dependencies:
* Python 3.5
* Scapy 3.0.0
    
### Tested on:
* Windows 10
* Kali 2016.2
    
### Usage:
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
  
### Common usage examples:
  
#### Deny port 
  thor.py -s 22 -i eth0
  
#### Deny IP
  thor.py -t 192.168.1.1 -i eth0
  
#### Deny IP + Port persistently. Be verbose.
  thor.py -t 192.168.1.1 -s 22 -i eth0 -p -v vv
  
### Notes:
  * On windows, there is an option to choose from a list of interfaces because windows sucks at this.
  * Currently beta, please let me knwo if you have issues

  
