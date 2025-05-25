from random_prime import *
import math
import base64
import json
import os

def gcd(a, b):
    """Calcul du PGCD avec l'algorithme d'Euclide"""
    while b:
        a, b = b, a % b
    return a

class RSA:
    def __init__(self):
        pass

    def generate_keys(self):
        """
        Génère une paire de clés RSA (publique et privée).
        """
        p = generate_512_bit_prime()    
        q = generate_512_bit_prime()
        
        while p == q:
            print("p et q identiques, régénération de q...")
            q = generate_512_bit_prime()
        
        n = p * q
        phi_n = (p - 1) * (q - 1)
        e = 65537  # Valeur courante pour e, souvent utilisée dans RSA
        
        try:
            d = pow(e, -1, phi_n)
        except ValueError:
            raise ValueError("Impossible de calculer l'inverse modulaire de e")

        public_key = (e, n)
        private_key = (d, n)
        
        return public_key, private_key, p, q

    def encrypt(self, message, public_key):
        """
        Chiffre un message en utilisant la clé publique RSA.
        """
        e, n = public_key
        
        # Convert message to integer
        if isinstance(message, str):
            message_bytes = message.encode('utf-8')
        else:
            message_bytes = message
            
        message_int = int.from_bytes(message_bytes, 'big')
        
        # Vérifier que le message est plus petit que n
        if message_int >= n:
            max_bytes = (n.bit_length() - 1) // 8
            raise ValueError(f"Message trop long. Taille maximale: {max_bytes} bytes, "
                            f"taille actuelle: {len(message_bytes)} bytes")
        
        # Encrypt the message
        encrypted_message = pow(message_int, e, n)
        return encrypted_message

    def decrypt(self, encrypted_message, private_key):
        """
        Déchiffre un message en utilisant la clé privée RSA.
        """
        d, n = private_key
        
        # Decrypt the message
        decrypted_message_int = pow(encrypted_message, d, n)
        
        # Convert integer back to bytes
        try:
            # Calculer le nombre de bytes nécessaires
            byte_length = (decrypted_message_int.bit_length() + 7) // 8
            if byte_length == 0:  # Cas où le message déchiffré est 0
                byte_length = 1
            
            decrypted_bytes = decrypted_message_int.to_bytes(byte_length, 'big')
            return decrypted_bytes
        except (OverflowError) as e:
            raise ValueError(f"Erreur lors du déchiffrement: {e}")

    def get_max_message_size(self, public_key):
        """Retourne la taille maximale du message en bytes"""
        e, n = public_key
        return (n.bit_length() - 1) // 8

def print_banner():
    print("=" * 60)
    print("          RSA ENCRYPTION/DECRYPTION TOOL")
    print("=" * 60)
    print()

def get_user_input():
    """Interface utilisateur pour les choix"""
    print("Choisissez une option:")
    print("1. Chiffrer un message")
    print("2. Déchiffrer un message")
    print("3. Générer une nouvelle paire de clés")
    print("4. Afficher les informations des clés actuelles")
    print("5. Sauvegarder les clés")
    print("6. Charger des clés")
    print("7. Quitter")
    print()

    choice = input("Votre choix (1-7): ").strip()
    return choice

def generate_keys_interface(rsa):
    """Interface pour générer des clés"""
    print("\n--- GÉNÉRATION DE CLÉS RSA ---")
    print("Génération en cours... (cela peut prendre quelques secondes)")
    
    try:
        public_key, private_key, p, q = rsa.generate_keys()
        
        print("\n--- CLÉS GÉNÉRÉES AVEC SUCCÈS ---")
        print(f"Clé publique (e, n):")
        print(f"  e: {public_key[0]}")
        print(f"  n: {public_key[1]}")
        print(f"\nClé privée (d, n):")
        print(f"  d: {private_key[0]}")
        print(f"  n: {private_key[1]}")
        print(f"\nFacteurs premiers:")
        print(f"  p: {p}")
        print(f"  q: {q}")
        
        max_size = rsa.get_max_message_size(public_key)
        print(f"\nTaille maximale du message: {max_size} bytes")
        
        return public_key, private_key
        
    except Exception as e:
        print(f"Erreur lors de la génération des clés: {e}")
        return None, None

def encrypt_message_interface(rsa, public_key):
    """Interface pour chiffrer un message"""
    if public_key is None:
        print("\nErreur: Aucune clé publique disponible. Générez d'abord des clés.")
        return None
    
    print("\n--- CHIFFREMENT RSA ---")
    
    # Entrer le message
    message = input("Entrez le message à chiffrer: ")
    if not message:
        print("Erreur: Le message ne peut pas être vide.")
        return None
    
    try:
        # Vérifier la taille du message
        max_size = rsa.get_max_message_size(public_key)
        if len(message.encode('utf-8')) > max_size:
            print(f"Erreur: Message trop long. Taille maximale: {max_size} bytes, "
                  f"taille actuelle: {len(message.encode('utf-8'))} bytes")
            return None
        
        # Chiffrement
        encrypted_data = rsa.encrypt(message, public_key)
        
        # Afficher les résultats
        print("\n--- RÉSULTATS DU CHIFFREMENT ---")
        print(f"Message original: {message}")
        print(f"Message chiffré (décimal): {encrypted_data}")
        print(f"Message chiffré (hex): {hex(encrypted_data)}")
        print(f"Message chiffré (base64): {base64.b64encode(str(encrypted_data).encode()).decode()}")
        
        return encrypted_data
        
    except Exception as e:
        print(f"Erreur lors du chiffrement: {e}")
        return None

def decrypt_message_interface(rsa, private_key):
    """Interface pour déchiffrer un message"""
    if private_key is None:
        print("\nErreur: Aucune clé privée disponible. Générez d'abord des clés.")
        return None
    
    print("\n--- DÉCHIFFREMENT RSA ---")
    
    # Format du message chiffré
    print("Format du message chiffré:")
    print("1. Décimal")
    print("2. Hexadécimal")
    print("3. Base64")
    
    format_choice = input("Votre choix (1-3): ").strip()
    
    encrypted_input = input("Entrez le message chiffré: ").strip()
    if not encrypted_input:
        print("Erreur: Le message chiffré ne peut pas être vide.")
        return None
    
    try:
        if format_choice == "1":
            encrypted_data = int(encrypted_input)
        elif format_choice == "2":
            encrypted_data = int(encrypted_input, 16)
        elif format_choice == "3":
            decoded_bytes = base64.b64decode(encrypted_input)
            encrypted_data = int(decoded_bytes.decode())
        else:
            print("Choix invalide.")
            return None
    except Exception as e:
        print(f"Erreur lors de la conversion du message chiffré: {e}")
        return None
    
    try:
        # Déchiffrement
        decrypted_bytes = rsa.decrypt(encrypted_data, private_key)
        decrypted_message = decrypted_bytes.decode('utf-8')
        
        # Afficher les résultats
        print("\n--- RÉSULTATS DU DÉCHIFFREMENT ---")
        print(f"Message déchiffré: {decrypted_message}")
        
        return decrypted_message
        
    except Exception as e:
        print(f"Erreur lors du déchiffrement: {e}")
        return None

def show_key_info(public_key, private_key):
    """Affiche les informations des clés actuelles"""
    print("\n--- INFORMATIONS DES CLÉS ---")
    
    if public_key is None or private_key is None:
        print("Aucune clé disponible. Générez d'abord des clés.")
        return
    
    print(f"Clé publique (e, n):")
    print(f"  e: {public_key[0]}")
    print(f"  n: {public_key[1]}")
    print(f"  Taille de n: {public_key[1].bit_length()} bits")
    
    print(f"\nClé privée (d, n):")
    print(f"  d: {private_key[0]}")
    print(f"  n: {private_key[1]}")
    
    max_size = (public_key[1].bit_length() - 1) // 8
    print(f"\nTaille maximale du message: {max_size} bytes")

def save_keys(public_key, private_key):
    """Sauvegarde les clés dans un fichier"""
    if public_key is None or private_key is None:
        print("\nErreur: Aucune clé à sauvegarder.")
        return
    
    filename = input("\nNom du fichier pour sauvegarder les clés (sans extension): ").strip()
    if not filename:
        filename = "rsa_keys"
    
    try:
        keys_data = {
            "public_key": {
                "e": public_key[0],
                "n": public_key[1]
            },
            "private_key": {
                "d": private_key[0],
                "n": private_key[1]
            }
        }
        
        with open(f"{filename}.json", 'w') as f:
            json.dump(keys_data, f, indent=2)
        
        print(f"Clés sauvegardées dans {filename}.json")
        
    except Exception as e:
        print(f"Erreur lors de la sauvegarde: {e}")

def load_keys():
    """Charge les clés depuis un fichier"""
    filename = input("\nNom du fichier contenant les clés (sans extension): ").strip()
    if not filename:
        print("Nom de fichier requis.")
        return None, None
    
    try:
        with open(f"{filename}.json", 'r') as f:
            keys_data = json.load(f)
        
        public_key = (keys_data["public_key"]["e"], keys_data["public_key"]["n"])
        private_key = (keys_data["private_key"]["d"], keys_data["private_key"]["n"])
        
        print(f"Clés chargées depuis {filename}.json")
        return public_key, private_key
        
    except FileNotFoundError:
        print(f"Fichier {filename}.json non trouvé.")
        return None, None
    except Exception as e:
        print(f"Erreur lors du chargement: {e}")
        return None, None

def main():
    """Fonction principale"""
    rsa = RSA()
    public_key = None
    private_key = None
    
    print("Bienvenue dans l'outil de chiffrement RSA!")
    print("Vous devez d'abord générer ou charger des clés pour commencer.")
    
    while True:
        print_banner()
        choice = get_user_input()
        
        if choice == "1":
            encrypt_message_interface(rsa, public_key)
        elif choice == "2":
            decrypt_message_interface(rsa, private_key)
        elif choice == "3":
            pub, priv = generate_keys_interface(rsa)
            if pub and priv:
                public_key, private_key = pub, priv
        elif choice == "4":
            show_key_info(public_key, private_key)
        elif choice == "5":
            save_keys(public_key, private_key)
        elif choice == "6":
            pub, priv = load_keys()
            if pub and priv:
                public_key, private_key = pub, priv
        elif choice == "7":
            print("Au revoir!")
            break
        else:
            print("Choix invalide. Veuillez choisir entre 1 et 7.")
        
        input("\nAppuyez sur Entrée pour continuer...")
        print("\n" * 2)

if __name__ == "__main__":
    main()