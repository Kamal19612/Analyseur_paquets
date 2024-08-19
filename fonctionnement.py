# lister le nom des interfaces
import pretty_errors
import psutil

def scanner() :
    import psutil
    # obtenir la liste des interfaces disponibles
    interfaces = psutil.net_if_addrs()
    # creer un tableau pour stocket les noms des interfaces
    interface_names = list(interfaces.keys())
    # afficher le nom des interfaces 
    print("les interfaces disponibles sont: ", interface_names )
    return interface_names 

# fonction permetant de recuperrer le port de l'utisisateur
def choix_port(list_interfaces) :
    interface_choisi=input("veiller faire votre choix de l'interface que vous voudriez utiliser : ")
    # dans la condition suivent, il va vérifier si l'interface choisi est la bonne et returner la fonction en question
    if interface_choisi in list_interfaces :
        return interface_choisi
    else :
        print("l'interface choisi ne se trouve pas parmis ")
        return choix_port(list_interfaces)



list_interfaces = scanner()
choix_port(list_interfaces)
