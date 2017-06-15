## Scanner port TCP service

Usage 
sudo python scanningAttack.py -p nPort --type=typeOfAttack addressIP
Require lib scapy
Type Of Attack
- SYN
- FIN/ACK
- ACK
- XmasTREE
- NULL

See file typeOfScanning for information of typeAttack

Example
sudo python2.7 scanningAttack.py -p 21,22,80 --type=SYN 192.168.1.80

NB if -p is not set, the ports examined are:
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

