## Scanner port TCP service

**Usage**
```bash
sudo python scanningAttack.py -p nPort --type=typeOfAttack addressIP
```

Requirements: 
```
scapy
```

Type Of Attacks implemented:
- SYN
- FIN/ACK
- ACK
- XmasTREE
- NULL

See file [typeOfScanning](typeOfScanning) for information of  all Attack's types.

Example
```
sudo python scanningAttack.py -p 21,22,80 --type=SYN 192.168.1.80
```

- If ```-p``` is not set, the ports examined are:
```
   80,     # http
   23,     # telnet
   22,     # ssh
   443,    # https
   3389,   # ms-term-serv
   445,    # microsoft-ds
   139,    # netbios-ssn
   21,     # ftp
   135,    # msrpc
   25     # smtp
```
- If type is not set is used ```SYN```
