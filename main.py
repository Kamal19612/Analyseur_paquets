import scapy.all as scapy
import fonctionnement as ft
import traitement_fichiers as tf

def main(): 
    # Attente de l'appui sur la touche "Entrée" pour démarrer
    input("Appuyez sur la touche 'Entrée' pour commencer...")
    # cette ligne nous permettera scanner les interfaces
    list_interfaces = ft.scanner()
    # la fonction choix_port permettera de scanner les interfaces, a l'utilisateur de faire son choix et de recuperer le choix fait par la variable port
    port=ft.choix_port(list_interfaces)
    tf.choix_requet(port)

main()