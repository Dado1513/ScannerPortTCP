import parseOptionsSimple
import configurationScannerTCP
import typePortScanning
import os
import sys
from scapy.all import *

def main():
    # gestire tutti i tipi di richieste passati come paramtri
    parseOptionsSimple.parsingOptions(sys.argv[1:])

    # oggetto che identifica tutti i parametri della scansione che si vuole attivre
    confScanner=configurationScannerTCP.configurationScannerAttack(
        configurationScannerTCP.destination,
        configurationScannerTCP.topports,
        configurationScannerTCP.typeOfScanning,
        configurationScannerTCP.numeroThread)

    #print (confScanner.topPort)
    TCP_REVERSE = dict((TCP_SERVICES[k], k) for k in TCP_SERVICES.keys())
    typePortScanning.scanningThreadStart(confScanner)

    for port in configurationScannerTCP.topports:
        try:
            print (port,typePortScanning.result[port],TCP_REVERSE[port])
        except KeyError:
            print (port,typePortScanning.result[port],"None")

if __name__ == "__main__":
    if os.geteuid == 0:
        main()
    else:
        print("You need to have root privileges to run this script.")
