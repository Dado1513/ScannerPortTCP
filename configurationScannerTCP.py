destination=""
numeroThread=5

# TOP TEN PORTS TCP
           # port   # service name

# porte classiche di default
topports = [80,     # http
            23,     # telnet
            22,     # ssh
            443,    # https
            3389,   # ms-term-serv
            445,    # microsoft-ds
            139,    # netbios-ssn
            21,     # ftp
            135,    # msrpc
            25]     # smtp



class configurationScannerAttack:
    def __init__(self,destinazione, porte = topports, typeAttack = "SYN" ,numeroThread=5):
        # contente l'indirizzo di destinazione
        self.destinazione=destinazione
        # contente i numro di threadUsati
        self.numeroThread=numeroThread
        # contente le porte che voglio scandire
        self.topPort=porte
        # type of attackl
        self.tipoAttacco=typeAttack



class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
