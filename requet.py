import traitement_fichier as ft

def requet_standard() :
    nombres_paquets = 50
    ft.capture_standard(nombres_paquets)



def requet_défini() : 
    nombres_paquets = input(" veiller entrer le nombre de paquet que vous vouler capturer: ")
    ft.capture_standard()


def requet_indéfini() : 
    ft.capture_indéfini()

requet_standard()