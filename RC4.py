# RC4 Algorithm - Interactive Implementation

import os
import base64
from binascii import hexlify, unhexlify


class RC4:
    def __init__(self):
        pass

    def key_scheduling_algorithm(self, key):
        """
        RC4 Key Scheduling Algorithm (KSA)
        
        Args:
            key (bytes): The secret key for encryption
            
        Returns:
            list: The initialized S-box (state array)
        """
        # Validate key length
        if not (1 <= len(key) <= 256):
            raise ValueError("La longueur de la clé doit être entre 1 et 256 bytes")
        
        # Initialize S-box with values 0 to 255
        S = list(range(256))
        
        # Key scheduling
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            # Swap S[i] and S[j]
            S[i], S[j] = S[j], S[i]
        
        return S

    def pseudo_random_generation_algorithm(self, S, length):
        """
        RC4 Pseudo-Random Generation Algorithm (PRGA)
        
        Args:
            S (list): The S-box from key scheduling
            length (int): Number of keystream bytes to generate
            
        Returns:
            bytes: The generated keystream
        """
        # Make a copy to avoid modifying original S-box
        S = S.copy()
        
        i = j = 0
        keystream = []
        
        for _ in range(length):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            
            # Swap S[i] and S[j]
            S[i], S[j] = S[j], S[i]
            
            # Generate keystream byte
            K = S[(S[i] + S[j]) % 256]
            keystream.append(K)
        
        return bytes(keystream)

    def encrypt(self, plaintext, key):
        """
        RC4 Encryption Function
        
        Args:
            plaintext (str or bytes): Data to encrypt
            key (str or bytes): Secret key
            
        Returns:
            bytes: Encrypted ciphertext
        """
        # Convert string to bytes if necessary
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        if isinstance(key, str):
            key = key.encode('utf-8')
        
        # Perform key scheduling
        S = self.key_scheduling_algorithm(key)
        
        # Generate keystream of same length as plaintext
        keystream = self.pseudo_random_generation_algorithm(S, len(plaintext))
        
        # XOR plaintext with keystream
        ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))
        
        return ciphertext

    def decrypt(self, ciphertext, key):
        """
        RC4 Decryption Function
        (Same as encryption due to XOR properties)
        
        Args:
            ciphertext (bytes): Data to decrypt
            key (str or bytes): Secret key
            
        Returns:
            bytes: Decrypted plaintext
        """
        # Convert key to bytes if necessary
        if isinstance(key, str):
            key = key.encode('utf-8')
        
        return self.encrypt(ciphertext, key)

    def analyze_keystream(self, key, length=100):
        """
        Analyze RC4 keystream properties for educational purposes
        
        Args:
            key (str or bytes): Secret key
            length (int): Length of keystream to analyze
            
        Returns:
            dict: Analysis results
        """
        if isinstance(key, str):
            key = key.encode('utf-8')
            
        S = self.key_scheduling_algorithm(key)
        keystream = self.pseudo_random_generation_algorithm(S, length)
        
        # Basic statistics
        byte_counts = [0] * 256
        for byte in keystream:
            byte_counts[byte] += 1
        
        return {
            'length': length,
            'unique_bytes': len([c for c in byte_counts if c > 0]),
            'most_frequent_byte': max(range(256), key=lambda x: byte_counts[x]),
            'max_frequency': max(byte_counts),
            'average_value': sum(keystream) / len(keystream),
            'keystream_preview': list(keystream[:20])  # First 20 bytes
        }


def print_banner():
    print("=" * 60)
    print("          RC4 ENCRYPTION/DECRYPTION TOOL")
    print("=" * 60)
    print()


def generate_random_key():
    """Generate a random key of specified length"""
    print("Longueur de la clé à générer:")
    print("1. 8 bytes (64 bits)")
    print("2. 16 bytes (128 bits)")
    print("3. 32 bytes (256 bits)")
    print("4. Longueur personnalisée")
    
    choice = input("Votre choix (1-4): ").strip()
    
    if choice == "1":
        length = 8
    elif choice == "2":
        length = 16
    elif choice == "3":
        length = 32
    elif choice == "4":
        try:
            length = int(input("Entrez la longueur en bytes (1-256): "))
            if not (1 <= length <= 256):
                print("Erreur: La longueur doit être entre 1 et 256 bytes.")
                return None
        except ValueError:
            print("Erreur: Veuillez entrer un nombre valide.")
            return None
    else:
        print("Choix invalide.")
        return None
    
    return os.urandom(length)


def get_user_input():
    """User interface for input"""
    print("Choisissez une option:")
    print("1. Chiffrer un message")
    print("2. Déchiffrer un message")
    print("3. Générer une clé aléatoire")
    print("4. Analyser un flux de clés (éducatif)")
    print("5. Quitter")
    print()

    choice = input("Votre choix (1-5): ").strip()
    return choice


def encrypt_message(rc4):
    """Interface for encrypting a message"""
    print("\n--- CHIFFREMENT RC4 ---")

    # Enter message
    message = input("Entrez le message à chiffrer: ")
    if not message:
        print("Erreur: Le message ne peut pas être vide.")
        return

    # Enter key
    print("\nOptions pour la clé:")
    print("1. Entrer une clé texte")
    print("2. Générer une clé aléatoire")
    print("3. Entrer une clé en hexadécimal")
    print("4. Entrer une clé en base64")

    key_choice = input("Votre choix (1-4): ").strip()

    if key_choice == "1":
        key = input("Entrez la clé: ")
        if not key:
            print("Erreur: La clé ne peut pas être vide.")
            return
    elif key_choice == "2":
        key = generate_random_key()
        if key is None:
            return
        print(f"Clé générée (hex): {key.hex()}")
        print(f"Clé générée (base64): {base64.b64encode(key).decode()}")
    elif key_choice == "3":
        key_hex = input("Entrez la clé en hexadécimal: ").strip()
        try:
            key = bytes.fromhex(key_hex)
        except ValueError:
            print("Erreur: Format hexadécimal invalide.")
            return
    elif key_choice == "4":
        key_b64 = input("Entrez la clé en base64: ").strip()
        try:
            key = base64.b64decode(key_b64)
        except Exception:
            print("Erreur: Format base64 invalide.")
            return
    else:
        print("Choix invalide.")
        return

    try:
        # Encryption
        encrypted_data = rc4.encrypt(message, key)

        # Display results
        print("\n--- RÉSULTATS DU CHIFFREMENT ---")
        print(f"Message original: {message}")
        if isinstance(key, str):
            print(f"Clé utilisée: {key}")
        else:
            print(f"Clé utilisée (hex): {key.hex()}")
            print(f"Clé utilisée (base64): {base64.b64encode(key).decode()}")
        print(f"Message chiffré (hex): {encrypted_data.hex()}")
        print(f"Message chiffré (base64): {base64.b64encode(encrypted_data).decode()}")

    except Exception as e:
        print(f"Erreur lors du chiffrement: {e}")


def decrypt_message(rc4):
    """Interface for decrypting a message"""
    print("\n--- DÉCHIFFREMENT RC4 ---")

    # Enter encrypted message
    print("Format du message chiffré:")
    print("1. Hexadécimal")
    print("2. Base64")

    format_choice = input("Votre choix (1-2): ").strip()

    encrypted_input = input("Entrez le message chiffré: ").strip()
    if not encrypted_input:
        print("Erreur: Le message chiffré ne peut pas être vide.")
        return

    try:
        if format_choice == "1":
            encrypted_data = bytes.fromhex(encrypted_input)
        elif format_choice == "2":
            encrypted_data = base64.b64decode(encrypted_input)
        else:
            print("Choix invalide.")
            return
    except Exception as e:
        print(f"Erreur lors de la conversion du message chiffré: {e}")
        return

    # Enter key
    print("\nFormat de la clé:")
    print("1. Texte")
    print("2. Hexadécimal")
    print("3. Base64")

    key_format = input("Votre choix (1-3): ").strip()
    key_input = input("Entrez la clé: ").strip()

    try:
        if key_format == "1":
            key = key_input
        elif key_format == "2":
            key = bytes.fromhex(key_input)
        elif key_format == "3":
            key = base64.b64decode(key_input)
        else:
            print("Choix invalide.")
            return
    except Exception as e:
        print(f"Erreur lors de la conversion de la clé: {e}")
        return

    try:
        # Decryption
        decrypted_data = rc4.decrypt(encrypted_data, key)
        decrypted_message = decrypted_data.decode('utf-8')

        # Display results
        print("\n--- RÉSULTATS DU DÉCHIFFREMENT ---")
        print(f"Message déchiffré: {decrypted_message}")

    except Exception as e:
        print(f"Erreur lors du déchiffrement: {e}")


def show_random_key():
    """Generate and display a random key"""
    print("\n--- GÉNÉRATION DE CLÉ ALÉATOIRE ---")
    key = generate_random_key()
    if key is None:
        return
        
    print(f"Clé aléatoire générée:")
    print(f"  Longueur: {len(key)} bytes")
    print(f"  Hexadécimal: {key.hex()}")
    print(f"  Base64: {base64.b64encode(key).decode()}")
    print(f"  ASCII (si imprimable): {key.decode('utf-8', errors='replace')}")


def analyze_keystream(rc4):
    """Analyze RC4 keystream for educational purposes"""
    print("\n--- ANALYSE DU FLUX DE CLÉS RC4 (ÉDUCATIF) ---")
    
    key = input("Entrez une clé pour l'analyse: ")
    if not key:
        print("Erreur: La clé ne peut pas être vide.")
        return
    
    try:
        length = int(input("Entrez la longueur du flux à analyser (défaut: 1000): ") or "1000")
        if length <= 0:
            print("Erreur: La longueur doit être positive.")
            return
    except ValueError:
        print("Erreur: Veuillez entrer un nombre valide.")
        return
    
    try:
        analysis = rc4.analyze_keystream(key, length)
        
        print("\n--- RÉSULTATS DE L'ANALYSE ---")
        print(f"Longueur du flux analysé: {analysis['length']} bytes")
        print(f"Nombre de bytes uniques: {analysis['unique_bytes']}/256")
        print(f"Byte le plus fréquent: {analysis['most_frequent_byte']} (apparitions: {analysis['max_frequency']})")
        print(f"Valeur moyenne: {analysis['average_value']:.2f}")
        print(f"Aperçu du flux (20 premiers bytes): {analysis['keystream_preview']}")
        
        # Show S-box initial state
        S = rc4.key_scheduling_algorithm(key.encode('utf-8'))
        print(f"S-box (10 premières valeurs): {S[:10]}")
        
    except Exception as e:
        print(f"Erreur lors de l'analyse: {e}")


def demonstrate_rc4_steps(rc4):
    """Demonstrate RC4 algorithm steps for educational purposes"""
    print("\n--- DÉMONSTRATION ÉTAPE PAR ÉTAPE ---")
    
    message = input("Entrez un message court (max 20 caractères): ")[:20]
    key = input("Entrez une clé courte (max 10 caractères): ")[:10]
    
    if not message or not key:
        print("Erreur: Le message et la clé ne peuvent pas être vides.")
        return
    
    print(f"\n📝 Message: '{message}'")
    print(f"🗝️  Clé: '{key}'")
    
    # Step 1: Key Scheduling
    print("\n--- ÉTAPE 1: ALGORITHME DE PLANIFICATION DE CLÉ (KSA) ---")
    key_bytes = key.encode('utf-8')
    S = rc4.key_scheduling_algorithm(key_bytes)
    print(f"S-box initialisée (10 premières valeurs): {S[:10]}")
    
    # Step 2: Generate keystream
    print("\n--- ÉTAPE 2: GÉNÉRATION DU FLUX DE CLÉS (PRGA) ---")
    message_bytes = message.encode('utf-8')
    keystream = rc4.pseudo_random_generation_algorithm(S, len(message_bytes))
    print(f"Flux de clés généré: {list(keystream)}")
    
    # Step 3: XOR operation
    print("\n--- ÉTAPE 3: OPÉRATION XOR ---")
    ciphertext = bytes(p ^ k for p, k in zip(message_bytes, keystream))
    print(f"Message (bytes): {list(message_bytes)}")
    print(f"Flux de clés:    {list(keystream)}")
    print(f"Résultat XOR:    {list(ciphertext)}")
    
    print(f"\n🔒 Message chiffré (hex): {ciphertext.hex()}")
    print(f"🔒 Message chiffré (base64): {base64.b64encode(ciphertext).decode()}")


def main_RC4():
    """Main function"""
    rc4 = RC4()

    while True:
        print_banner()
        choice = get_user_input()

        if choice == "1":
            encrypt_message(rc4)
        elif choice == "2":
            decrypt_message(rc4)
        elif choice == "3":
            show_random_key()
        elif choice == "4":
            analyze_keystream(rc4)
        elif choice == "5":
            print("Au revoir!")
            break
        else:
            print("Choix invalide. Veuillez choisir entre 1 et 5.")

        # Hidden option for demonstration
        if choice.lower() == "demo":
            demonstrate_rc4_steps(rc4)

        input("\nAppuyez sur Entrée pour continuer...")
        print("\n" * 2)

