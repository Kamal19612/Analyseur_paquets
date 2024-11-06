import threading
from scapy.all import sniff, IP, TCP, UDP, ARP, Ether
import keyboard
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

# Liste pour stocker les paquets capturés
captured_packets = []
port = "Wi-Fi"

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

def requet_indefini():
    global capturing, packet_data
    capturing = True
    packet_data = []
    
    print("Veuillez appuyer sur la touche 'q' pour arrêter la capture des paquets.")
    
    def process_packet(packet):
        if capturing:  # Vérifie si la capture est encore active
            afficher_details_packet(packet)
            packet_data.append(packet)
    
    def start_capture():
        sniff(prn=process_packet, stop_filter=lambda p: not capturing)
    
    capture_thread = threading.Thread(target=start_capture)
    capture_thread.start()
    
    while capturing:
        if keyboard.is_pressed('q'):
            capturing = False
    
    capture_thread.join()
    print(f"Capture terminée. {len(packet_data)} paquets capturés.")
    df = pd.DataFrame(packet_data)
    print("Colonnes du DataFrame :", df.columns)  # Ajoutez cette ligne pour déboguer
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
    proto_name, details, ip_src, ip_dst, request_type = "Inconnu", "Détails inconnus", "Inconnu", "Inconnu", "Inconnu"
    
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

def statistic(df):
    # Générer des statistiques
    print(f"Nombre de paquets capturés : {len(df)}")
    
    if 'Protocole' in df.columns:
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
    else:
        print("Aucune colonne 'Protocole' trouvée dans le DataFrame.")

# Définir le port globalement
port = "Wi-Fi"

# Exemple d'appel
choix_requet()
