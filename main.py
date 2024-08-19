import fonctionnement as mf
import scapy.all as scapy
import traitement_fichier as tf

while True :
    list_interfaces = mf.scanner()
    # la fonction choix_port permettera de scanner les interfaces, a l'utilisateur de faire son choix et de recuperer le choix fait
    port = mf.choix_port(list_interfaces)
    # ouvrir l'interface de capture
    iface = scapy.conf.iface
    # Définir le filtre de capture
    filter = "port " + str(port)
    # lancer la requet par le choix qu'il fera
    tf.choix_requet()