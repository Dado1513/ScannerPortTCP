import getopt
import sys
import configurationScannerTCP


def help():
    print """

        SCANNER TCP written by Dado1513

        for usage must be Super User, based on scapy

        [usage] sudo python -p PORT --type=typeOfAttack <target>

    """



# vettore di stringhe per evitare type di attacchi non riconosciuti
tipoAttacchi=["SYN","FIN/ACK","ACK","XmasTREE","NULL"]
# type SYN
# type FIN/ACK
# type ACK
# type XmasTREE
# type NULL


# p seguito dalle porte che si vogliono interrogare
def parsingOptions(args):

    options,target=getopt.getopt(args,"hp:",['type='])
    if target is not None and len(target) > 0:
        configurationScannerTCP.destination=target

        for opt in options:
            if(opt[0]=="--type"):
                if(str(opt[1]) in tipoAttacchi):
                    #imposto il tipo di attacco
                    configurationScannerTCP.typeOfScanning=opt[1]
                else:
                    print(configurationScannerTCP.bcolors.WARNING+"Type of attack not recognize"+configurationScannerTCP.bcolors.ENDC)
                    help()
                    sys.exit(0)

            elif(opt[0]=="-p"):
                #le porte che si vogliono scansionare
                #print (opt[1])
                porte=str(opt[1]).split(",")
                configurationScannerTCP.topports=[int(port) for port in porte]
                #print configuration.topports;

            elif(opt[0]=="-h"):
                help()
                sys.exit(0)

            else:
                help()
                sys.exit(0)
    else:
        help()
        sys.exit(0)
