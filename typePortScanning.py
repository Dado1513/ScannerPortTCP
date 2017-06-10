from scapy.all import *
import configurationScannerTCP
import threading
import Queue
import parseOptionsSimple
result={}

# type of richiesta ->
#response = sr1(IP(dst=scanner.target)/TCP(dport=port, flags="S"),verbose=False, timeout=0.2)
#response=sr1(IP(dst='192.168.33.10')/TCP(dport=22,flags="A"),timeout=0.2)


#            if response:
                # flags is 18 if SYN,ACK received
                # i.e port is open
                # if 4 -> RST received
                # 20 -> RA
                # 1-> F
                # 17 -> FA
                # 32 -> U
                # 8 -> P
#                if response[TCP].flags == 18:
#                    scanner.output += "%5d\tOPEN\n" %port
# reverse map TCP_SERVICES
# siccome TCP_SERVICES['service'] -> si ottien il numero della porta
# TCP_REVERSE = dict((TCP_SERVICES[k], k) for k in TCP_SERVICES.keys())
# ora TCP_REVERSE[numero_porta] ottengo il servizio
#



def scanningSyn(destinazione,porta):
    response = sr1(IP(dst=destinazione) / TCP(dport=porta, flags="S"), verbose=False,
                      timeout=0.2)
    if(response):
        #print (response[TCP].flags)
        if response[TCP].flags == 18:
            #porta aperta
            return True
        else:
            return False
    else:
        return False

def scanningFin(destinazione,porta):

    """
     scan Fin , si invia un pacchetto FIN se la porta e chiusa ri riceve un
     pacchetto RST o RST/ACK  , se non si riceve niente allora molto probabilmente
     e aperta o filtrata
     Funziona quasi esclusivamente su stack TCP/IP basati su Unix
     perche gli altri stack rispondo quasi sempre con rst

    :param destinazione: Ip destinazione
    :param porta: porta da scandire
    :return: True se la porta e aperta
           : False se la porta e chiusa
    """

    response = sr1(IP(dst=destinazione) / TCP(dport=porta, flags="F"),verbose=False, timeout=0.2);
    if(response):
        try:
            if(response[TCP].flags==20 or response[TCP].flags==4):
                # porta quasi sicuramente chiusa
                return False
            else:
                return True
        except IndexError:
            if(response[TCPerror].flags==41):
                # la porta e filtrata
                return True

    else:
        return True


def scanningAck(destinazione,porta):
    """
    Scansione ACK TCP Questa tecnica e usata per mappare i ruleset dei firewall (regole per accedere a Internet per ogni applicazione).
    Puo aiutare a determinare se il firewall e un semplice filtro di pacchetti che consente solo connessioni con il bit ACK impostato,
    oppure un firewall con controllo sullo stato che opera un filtro avanzato.
    Si invia un pacchetto ACK al bersaglio se allo scadere del timeout non si e ancora ricevuto niente si deduce che la porta e filtrata.
    Mentre se viene ricevuto e siccome non ha una connessione attiva il bersaglio invia un pacchetto RST o FIN
    per indicare di chiudere la connessione.( https://it.wikipedia.org/wiki/ACK_scan )

    :param destinazione:
    :param porta:
    :return:
    """
    response = sr1(IP(dst=destinazione) / TCP(dport=porta, flags="A"), verbose=False,
                   timeout=0.2)
    if (response):
        # print (response[TCP].flags)
        if response[TCP].flags == 4 :
            # porta chiusa o aperta non lo so
            return True
        else:
            # porta chiusa o aperta
            return True
    else:
        # porta filtrata molto probabilmente
        return False


def scanningXmasTree(destinazione,porta):
    response = sr1(IP(dst=destinazione) / TCP(dport=porta,flags="FUP"), verbose=False,
                   timeout=0.2)
    if(response):
        # riceve RSTACK
        try:
            if(response[TCP].flags==20):
                # la prta e chiusa abbiamo ricevuto RA
                return "chiusa"
        except IndexError:
            #allora l index [TCP] non esiste ho rivenuto tre pacchetti di qui uno TCPerror
            if(response[TCPerror].flags==41):
                # la porta e filtrata
                return True
        # filtrata
        return False
    else:
        # aperta/filtrata
        return True


def scanningNull(destinazione,porta):
    response = sr1(IP(dst=destinazione) / TCP(dport=porta ), verbose=False,
                   timeout=0.2)
    if (response):
        # print (response[TCP].flags)
        if response[TCP].flags == 18:
            # porta chiusa o aperta non lo so
            return True
        else:
            # porta chiusa o aperta
            return False
    else:
        # porta filtrata molto probabilmente
        return False


# ogni thread esegue le scansioni
class scanningThred(threading.Thread):
    def __init__(self,portlist,type,destination,tid,indexAttack):
        threading.Thread.__init__(self)
        self.portList=portlist
        self.type=type
        self.destination=destination
        self.tid=tid
        self.indexAttack=indexAttack

    def run(self):
        while True:
            port=0
            try:
                port=self.portList.get(timeout=1)
            except Queue.Empty:
                return

            # sono gia sicuro che il valore e corretto
            # ora ottengo l'indice
            #print (index)


            if(self.indexAttack==0):
                # attacco tipo synack
                # si invia syn e si aspetta la risposta con
                # flag syn/ack
                verifica= scanningSyn(self.destination,port)
                # qua posso vedere se la porta e aperta o meno
                if(verifica):
                    #print (port,"open",self.tid)
                    result[port]="OPEN"
                else:
                    result[port]="CLOSE"
                    #print (port,"close",self.tid)

            elif(self.indexAttack==1):
                # si invia un pacchetto fin, e si riceve un packet
                # rst per tutte le porte chiuse , funziona
                # specialmente su stack tcp/ip basati su Unix
                verifica=scanningFin(self.destination,port)

                if(verifica):
                    #print(port,"open",self.tid)
                    result[port]="OPEN"
                else:
                    result[port]="CLOSE"
                    #print (port,"close",self.tid)

                # fin scan

            elif(self.indexAttack==2):
                # ack attack
                verifica=scanningAck(self.destination,port)

                if(verifica):
                    #print (port,"unfiltred",self.tid)
                    result[port]="UNFILTRED"
                else:
                    result[port]="FILTRED"
                    #print (port,"filtred",self.tid)
                pass

            # not work
            elif(self.indexAttack==3):
                #XmasTree scan
                verifica=scanningXmasTree(self.destination,port)
                #print (verifica)
                if(verifica):
                    if(verifica=="chiusa"):
                        #print (port,"close",self.tid)
                        result[port]="CLOSE"
                    else:
                        result[port]="OPEN|FILTRED"
                        #print (port,"open|filtred",self.tid)
                else:
                    result[port]="FILTRED"
                    #print (port,"filtred",self.tid)

            elif(self.indexAttack==4):
                # Null scan
                verifica=scanningNull(self.destination,port)
                if(verifica):
                    #print (port,"open",self.tid)
                    result[port]="OPEN"
                else:
                    result[port]="CLOSE"
                    #print (port,"close",self.tid)
                pass


            #ora qua deve verificare tutti i diversi casi di tipi di scansioni

            self.portList.task_done()



def scanningThreadStart(confScanner):

    # effettiva rchiesta

    #richiesta generale  alla destinazione alla porta 0 e con flag S (quindo SYN)
    portList=Queue.Queue()
    indexAttack = parseOptionsSimple.tipoAttacchi.index(confScanner.tipoAttacco)

    for x in confScanner.topPort:
        portList.put(x)

    threads=[]
    for  i in range(0, confScanner.numeroThread):
        thread=scanningThred(portList,confScanner.tipoAttacco,confScanner.destinazione,i,indexAttack)
        thread.start()
        threads.append(thread)

    portList.join()

    for t in threads:
        t.join()
