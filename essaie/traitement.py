# module traitement de fichier

from scapy.all import *
import keyboard
import pandas as pd
import seaborn as sns
from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP
import matplotlib.pyplot as plt
import multiprocessing


def choix_requet() : 
    # recupération de l'interface 
    # list_interfaces = ft.scanner()
    # port = ft.choix_port(list_interfaces)
    print("Trois options s'offre à vous")
    print("1. lancer une requette standard (50 paquets définit par défaut) ")
    print("2. lancer une requette manuelle ")
    print("3. lancer une requette indéfini (signature du paquet continuelle jusqu'a arrèt)")
    option=int(input("selon l'option choisi entrer le chiffre correspondant: "))
    if option == 1 :
        return capture_standard(50) 
    elif option == 2 :
        return requet_defini()
    elif option == 3:
        return capture_indefini()
    else :
        print("Vous avez fait une erreur sur l'option choisi, veiller réseiller")
        return choix_requet()



def requet_defini() : 
    nombres_paquets = int(input(" veiller entrer le nombre de paquet que vous vouler capturer: "))
    capture_standard(nombres_paquets)



# def capture_standard (nombres_paquets):
    global packet_data
    packet_data = []  # Réinitialiser la liste de paquets
    # sniffer le nombre de paquets demander 
    analyseur_packet(interface, count=nombres_paquets)
    sniff(count=nombres_paquets, prn=Analyse_packet)
    # cree une DataFrame avec python
    df = pd.DataFrame(packet_data, columns=["IP Source", "IP Destination", "SOURCE Sport", "DESTINATION Dport", "Protocol", "Request Type"])
    # Afficher la DataFrame
    print(df)
    return df
    
    # Générer des statistiques
    print(f"Nombre de paquets capturés : {len(packet_data)}")
    protocol_counts = df['Protocol'].value_counts()
    print("Répartition des protocoles :")
    print(protocol_counts)
    top_ips = df['IP Source'].value_counts().head(10)
    print("Top 10 des IP sources les plus actives :")
    print(top_ips)
    request_type_counts = df['Request Type'].value_counts()
    print("Nombre de paquets par type de requête :")
    print(request_type_counts) 
    
    # Afficher les graphiques sur des tableaux différents
    
    # Répartition des protocoles
    plt.figure()
    plt.bar(protocol_counts.index, protocol_counts.values)
    plt.xlabel('Protocol')
    plt.ylabel('Count')
    plt.title('Répartition des protocoles')
    plt.show()
    
    # Top 10 des IP sources les plus actives
    plt.figure()
    plt.bar(top_ips.index, top_ips.values)
    plt.xlabel('IP Source')
    plt.ylabel('Count')
    plt.title('Top 10 des IP sources les plus actives')
    plt.show()
    
    # Nombre de paquets par type de requête
    plt.figure()
    plt.pie(request_type_counts.values, labels=request_type_counts.index, autopct='%1.1f%%')
    plt.title('Nombre de paquets par type de requête')
    plt.show()




def capture_indefini():
    global packet_data
    packet_data = []
    print("Veillez appuyer la touche Q pour arrêter la capture des paquets")
    #print_info = lambda packet: print(packet.summary())
    # packet.summary() renvoie une chaine de caractère qui resume les informations du paquet
    
    # Lancer la capture des paquets dans un thread séparé
    sniff(prn=Analyse_packet, stop_filter=lambda p: keyboard.is_pressed('q'))
    # sniff(prn=...) permet d'appliquet une fonction à chaque paquet capturer
    # stop_filter permet d'arrêter la capture lorsque la fonction renvoie True
    df = pd.DataFrame(packet_data, columns=["IP Source", "IP Destination", "SOURCE Sport", "DESTINATION Dport", "Protocol", "Request Type"])
    print(df)
    statistic(df)


# def Analyse_packet(packet):
    global packet_data
    if IP in packet:
        ip_src= packet[IP].src
        ip_dst= packet[IP].dst
        protocol = packet[IP].proto
        src_port = packet[IP].sport
        dst_port = packet[IP].dport
        request_type = ""
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            request_type = "TCP"
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            request_type = "UDP"
        elif ICMP in packet:
            src_port = packet[ICMP].type
            dst_port = packet[ICMP].code
            request_type = "ICMP"
        else:
            src_port = None
            dst_port = None
            request_type = "other"
        
        packet_data.append({"IP Source": ip_src, "IP Destination": ip_dst, "SOURCE Sport": src_port, "DESTINATION Dport": dst_port, "Protocol": protocol, "Request Type": request_type})

captured_packets = []

def afficher_details_packet(packet):
    if ARP in packet:
        proto_name = "ARP"
        details = f"{packet[ARP].psrc} -> {packet[ARP].pdst}"
    elif IP in packet:
        proto = packet[IP].proto
        if proto == 6:  # TCP
            dport = packet[TCP].dport
            sport = packet[TCP].sport
            if dport == 80 or sport == 80:
                proto_name = "HTTP"
            elif dport == 443 or sport == 443:
                proto_name = "HTTPS"
            elif dport == 21 or sport == 21:
                proto_name = "FTP"
            elif dport == 25 or sport == 25:
                proto_name = "SMTP"
            elif dport == 110 or sport == 110:
                proto_name = "POP3"
            elif dport == 143 or sport == 143:
                proto_name = "IMAP"
            elif dport == 53 or sport == 53:
                proto_name = "DNS"
            else:
                proto_name = "TCP"
            details = f"{packet[IP].src}:{sport} -> {packet[IP].dst}:{dport}"
        elif proto == 17:  # UDP
            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                proto_name = "DNS"
            else:
                proto_name = "UDP"
            details = f"{packet[IP].src} -> {packet[IP].dst}"
        elif proto == 1:  # ICMP
            proto_name = "ICMP"
            details = f"{packet[IP].src} -> {packet[IP].dst}"
        else:
            proto_name = "Inconnu"
            details = f"{packet[IP].src} -> {packet[IP].dst}"
    else:
        proto_name = "Non IP"
        details = "Détails inconnus"
    
    captured_packets.append({'Protocole': proto_name, 'Détails': details})
    print(f"Paquet {proto_name} capturé : {details}")

nombre_paquets = 10
def analyseur_packet(interface, count=nombre_paquets):
    print(f"Capture de {count} paquets sur l'interface {interface or 'par défaut'}...")
    sniff(iface=interface, count=count, prn=afficher_details_packet)
    print(f"Capture terminée. {len(captured_packets)} paquets capturés.")
    # Affichage des résultats dans une DataFrame
    df = pd.DataFrame(captured_packets)
    print(df)

# Exemple d'utilisation
# analyseur_packet(interface='Wi-Fi', count=10)


# nombres_paquets = 25
# capture_standard (nombres_paquets)
# captur = capture_standard (nombres_paquets)
# statistic (captur)

from scapy.all import sniff, ARP, IP, TCP, UDP, ICMP, Ether
import pandas as pd

captured_packets = []
def afficher_details_packet(packet):
    if ARP in packet:
        proto_name = "ARP"
        details = f"{packet[ARP].psrc} -> {packet[ARP].pdst}"
    elif IP in packet:
        proto_name, details = handle_ip_packet(packet)
    elif Ether in packet:
        proto_name = "Ethernet"
        details = f"{packet[Ether].src} -> {packet[Ether].dst} (Type: {packet[Ether].type})"
    else:
        proto_name = "Inconnu"
        details = "Détails inconnus"
    captured_packets.append({'Protocole': proto_name, 'Détails': details})
    print(f"Paquet {proto_name} capturé : {details}")

def handle_ip_packet(packet):
    proto = packet[IP].proto
    if proto == 6:  # TCP
        return handle_tcp_packet(packet)
    elif proto == 17:  # UDP
        return handle_udp_packet(packet)
    elif proto == 1:  # ICMP
        return "ICMP", f"{packet[IP].src} -> {packet[IP].dst}"
    else:
        return "IP Inconnu", f"{packet[IP].src} -> {packet[IP].dst} (Proto: {proto})"

def handle_tcp_packet(packet):
    sport = packet[TCP].sport
    dport = packet[TCP].dport
    known_ports = {
        80: "HTTP",
        443: "HTTPS",
        21: "FTP",
        25: "SMTP",
        110: "POP3",
        143: "IMAP",
        53: "DNS"
    }
    proto_name = known_ports.get(dport, known_ports.get(sport, "TCP"))
    details = f"{packet[IP].src}:{sport} -> {packet[IP].dst}:{dport}"
    return proto_name, details

def handle_udp_packet(packet):
    sport = packet[UDP].sport
    dport = packet[UDP].dport
    if dport == 53 or sport == 53:
        proto_name = "DNS"
    else:
        proto_name = "UDP"
    details = f"{packet[IP].src}:{sport} -> {packet[IP].dst}:{dport}"
    return proto_name, details

def analyseur_packet(interface=None, count=30):
    print(f"Capture de {count} paquets sur l'interface {interface or 'par défaut'}...")
    sniff(iface=interface, count=count, prn=afficher_details_packet)
    print(f"Capture terminée. {len(captured_packets)} paquets capturés.") 
    # Affichage des résultats dans une DataFrame
    df = pd.DataFrame(captured_packets)
    print(df)

# Exemple d'appel
# analyseur_packet(interface="Wi-Fi", count=20)


# debut du programme
from scapy.all import sniff, IP, TCP, UDP, ARP, Ether
import keyboard
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import threading


global port
# Liste pour stocker les paquets capturés
captured_packets = []

def requet_standard():
    nombre_pack = 20
    df = analyseur_packet(interface=port, count=nombre_pack)
    statistic(df)

def requet_defini():
    try:
        nombre_pack = int(input("Quel est le nombre de paquets que vous voulez capturer : "))
        df = analyseur_packet(interface=port, count=nombre_pack)
        statistic(df)
    except ValueError:
        print("Veuillez entrer un nombre valide.")
        requet_defini()

import threading
import signal

def requet_indefini():
    global packet_data
    packet_data = []
    print("Veuillez appuyer sur la touche 'Q' pour arrêter la capture des paquets.")
    
    # Variable pour contrôler l'arrêt de la capture
    stop_sniffing = threading.Event()
    
    def process_packet(packet):
        # Affiche les détails du paquet et l'ajoute à la liste packet_data
        afficher_details_packet(packet)
        packet_data.append(packet)
    
    def capture():
        sniff(prn=process_packet, stop_filter=lambda p: stop_sniffing.is_set())
    
    # Thread pour capturer les paquets
    capture_thread = threading.Thread(target=capture)
    capture_thread.start()
    
    # Thread pour surveiller l'appui sur la touche 'Q'
    def check_for_q():
        while True:
            if keyboard.is_pressed('q'):
                print("Touche 'Q' pressée, arrêt de la capture...")
                stop_sniffing.set()
                break
            
    keyboard_thread = threading.Thread(target=check_for_q)
    keyboard_thread.start()
    
    capture_thread.join()  # Attendre la fin du thread de capture
    print(f"Capture terminée. {len(packet_data)} paquets capturés.")
    df = pd.DataFrame(packet_data)
    statistic(df)


def choix_requet(): 
    print("Trois options s'offrent à vous")
    print("1. Lancer une requête standard (20 paquets par défaut)")
    print("2. Lancer une requête manuelle")
    print("3. Lancer une requête indéfinie (capture continue jusqu'à arrêt)")
    
    try:
        option = int(input("Entrez le chiffre correspondant à votre option : "))
        if option == 1:
            requet_standard() 
        elif option == 2:
            requet_defini()
        elif option == 3:
            requet_indefini()
        else:
            print("Erreur : option non reconnue. Veuillez réessayer.")
            choix_requet()
    except ValueError:
        print("Veuillez entrer un nombre valide.")
        choix_requet()

def afficher_details_packet(packet):
    if ARP in packet:
        proto_name = "ARP"
        details = f"{packet[ARP].psrc} -> {packet[ARP].pdst}"
        ip_src = packet[ARP].psrc
        ip_dst = packet[ARP].pdst
        request_type = "ARP"
    elif IP in packet:
        proto_name, details, ip_src, ip_dst, request_type = handle_ip_packet(packet)
    elif Ether in packet:
        proto_name = "Ethernet"
        details = f"{packet[Ether].src} -> {packet[Ether].dst} (Type: {packet[Ether].type})"
        ip_src = packet[Ether].src
        ip_dst = packet[Ether].dst
        request_type = "Ethernet"
    else:
        proto_name = "Inconnu"
        details = "Détails inconnus"
        ip_src = "Inconnu"
        ip_dst = "Inconnu"
        request_type = "Inconnu"
    
    captured_packets.append({
        'Protocole': proto_name,
        'Détails': details,
        'IP Source': ip_src,
        'IP Destination': ip_dst,
        'Request Type': request_type
    })
    print(f"Paquet {proto_name} capturé : {details}")

def handle_ip_packet(packet):
    proto = packet[IP].proto
    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    
    if proto == 6:  # TCP
        proto_name, details = handle_tcp_packet(packet)
    elif proto == 17:  # UDP
        proto_name, details = handle_udp_packet(packet)
    elif proto == 1:  # ICMP
        proto_name = "ICMP"
        details = f"{ip_src} -> {ip_dst}"
    else:
        proto_name = "IP Inconnu"
        details = f"{ip_src} -> {ip_dst} (Proto: {proto})"
    
    return proto_name, details, ip_src, ip_dst, proto_name

def handle_tcp_packet(packet):
    sport = packet[TCP].sport
    dport = packet[TCP].dport
    known_ports = {
        80: "HTTP",
        443: "HTTPS",
        21: "FTP",
        25: "SMTP",
        110: "POP3",
        143: "IMAP",
        53: "DNS"
    }
    proto_name = known_ports.get(dport, known_ports.get(sport, "TCP"))
    details = f"{packet[IP].src}:{sport} -> {packet[IP].dst}:{dport}"
    return proto_name, details

def handle_udp_packet(packet):
    sport = packet[UDP].sport
    dport = packet[UDP].dport
    if dport == 53 or sport == 53:
        proto_name = "DNS"
    else:
        proto_name = "UDP"
    details = f"{packet[IP].src}:{sport} -> {packet[IP].dst}:{dport}"
    return proto_name, details

def analyseur_packet(interface=None, count=30):
    print(f"Capture de {count} paquets sur l'interface {interface or 'par défaut'}...")
    sniff(iface=interface, count=count, prn=afficher_details_packet)
    print(f"Capture terminée. {len(captured_packets)} paquets capturés.") 
    # Affichage des résultats dans une DataFrame
    df = pd.DataFrame(captured_packets)
    print(df)
    return df


import seaborn as sns
import matplotlib.pyplot as plt

def statistic(df):
    # Générer des statistiques
    print(f"Nombre de paquets capturés : {len(df)}")
    
    protocol_counts = df['Protocole'].value_counts()
    print("Répartition des protocoles :")
    print(protocol_counts)
    
    # Graphique 1 : Répartition des protocoles
    plt.figure(figsize=(8, 6))
    sns.countplot(x='Protocole', data=df)
    plt.title('Répartition des protocoles')
    plt.show(block=False)  # Affiche le graphique dans une nouvelle fenêtre
    
    # Graphique 2 : Répartition des IP sources
    plt.figure(figsize=(8, 6))
    sns.countplot(x='IP Source', data=df)
    plt.title('Répartition des IP sources')
    plt.show(block=False)  # Affiche le graphique dans une nouvelle fenêtre
    
    # Graphique 3 : Répartition des types de requête
    plt.figure(figsize=(8, 6))
    sns.countplot(x='Request Type', data=df)
    plt.title('Répartition des types de requête')
    plt.show(block=False)  # Affiche le graphique dans une nouvelle fenêtre
    
    # Garder les fenêtres ouvertes jusqu'à ce que l'utilisateur appuie sur Entrée
    input("Appuyez sur Entrée pour fermer les graphiques et terminer le programme.")


# Exemple d'appel
#df = analyseur_packet(interface=port, count=20)
#statistic(df)



# Définir le port globalement
port = "Wi-Fi"
# Exemple d'appel
choix_requet()
