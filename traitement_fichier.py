# module traitement de fichier

from scapy.all import *
import keyboard
import pandas as pd
import seaborn as sns
from scapy.all import IP, TCP, UDP, ICMP
import matplotlib.pyplot as plt
import pretty_errors
import fonctionnement as ft
import requet
import multiprocessing

def choix_requet() : 
    # recupération de l'interface 
    # list_interfaces = ft.scanner()
    # port = ft.choix_port(list_interfaces)
    print("Trois options s'offre à vous")
    print("1. lancer une requette standard (50 paquets définit par défaut) ")
    print("2. lancer une requette manuelle ")
    print("3. lancer une requette indéfini (signature du paquet continuelle jusqu'a arrèt)")
    option=input("selon l'option choisi entrer le chiffre correspondant: ")
    if option==1 :
        return requet.requet_standard() 
    elif option==2 :
        return requet.requet_manuelle()
    elif option==3:
        return requet.requet_indéfini()
    else :
        print("Vous avez fait une erreur sur l'option choisi, veiller réseiller")


def capture_standard (nombres_paquets):
    global packet_data
    packet_data = []  # Réinitialiser la liste de paquets
    # sniffer le nombre de paquets demander 
    sniff(count=nombres_paquets, prn=Analyse_packet)
    # cree une DataFrame avec python
    df = pd.DataFrame(packet_data, columns=["IP Source", "IP Destination", "SOURCE Sport", "DESTINATION Dport", "Protocol", "Request Type"])
    # Afficher la DataFrame
    print(df)
    return df
    
    """ # Générer des statistiques
    print(f"Nombre de paquets capturés : {len(packet_data)}")
    protocol_counts = df['Protocol'].value_counts()
    print("Répartition des protocoles :")
    print(protocol_counts)
    top_ips = df['IP Source'].value_counts().head(10)
    print("Top 10 des IP sources les plus actives :")
    print(top_ips)
    request_type_counts = df['Request Type'].value_counts()
    print("Nombre de paquets par type de requête :")
    print(request_type_counts) """
    
    
    """ # Afficher les graphiques simultanément
    fig, axs = plt.subplots(3, 1, figsize=(10, 15))
    
    # Répartition des protocoles
    axs[0].bar(protocol_counts.index, protocol_counts.values)
    axs[0].set_xlabel('Protocol')
    axs[0].set_ylabel('Count')
    axs[0].set_title('Répartition des protocoles')
    
    # Top 10 des IP sources les plus actives
    axs[1].bar(top_ips.index, top_ips.values)
    axs[1].set_xlabel('IP Source')
    axs[1].set_ylabel('Count')
    axs[1].set_title('Top 10 des IP sources les plus actives')
    
    # Nombre de paquets par type de requête
    axs[2].pie(request_type_counts.values, labels=request_type_counts.index, autopct='%1.1f%%')
    axs[2].set_title('Nombre de paquets par type de requête')
    
    plt.tight_layout()
    plt.show() """
    
    """ # Afficher les graphiques sur des tableaux différents
    
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
    plt.show() """



def capture_indéfini():
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


def Analyse_packet(packet):
    global packet_data
    if IP in packet:
        ip_src= packet[IP].src
        ip_dst= packet[IP].dst
        protocol = packet[IP].proto
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

def statistic (df) :
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
    
    
    sns.countplot(x='Protocol', data=df)
    plt.title('Répartition des protocoles')
    plt.show()
    
    sns.countplot(x='IP Source', data=df)
    plt.title('Répartition des IP sources')
    plt.show()
    
    sns.countplot(x='Request Type', data=df)
    plt.title('Répartition des types de requête')
    plt.show()

nombres_paquets = 25
capture_standard (nombres_paquets)
captur = capture_standard (nombres_paquets)
statistic (captur)