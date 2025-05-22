from scapy.all import get_if_list


def choose_interface():
    interfaces = get_if_list()
    print("Interfaces disponibles :")
    for idx, iface in enumerate(interfaces):
        print(f"{idx}. {iface}")

    try:
        choix = input("Sélectionnez l’interface (numéro, défaut=0) : ")
        if choix.strip() == "":
            return interfaces[0]
        index = int(choix)
        return interfaces[index]
    except (ValueError, IndexError):
        print("❌ Mauvais choix. Interface par défaut utilisée.")
        return interfaces[0] if interfaces else ""
