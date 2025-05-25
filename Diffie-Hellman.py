import random
import hashlib
import base64
from math import gcd
import os


class DiffieHellman:
    def __init__(self):
        self.p = None  # Prime modulus
        self.g = None  # Generator
        self.private_key = None
        self.public_key = None
        self.shared_secret = None
        self.session_key = None
        
    def generate_random_prime(self, bits):
        """Generate a large prime number of specified bit length"""
        print(f"Génération d'un nombre premier de {bits} bits...")
        
        while True:
            candidate = random.getrandbits(bits)
            candidate |= (1 << bits - 1) | 1  # Set MSB and LSB to 1
            
            if self.is_prime_miller_rabin(candidate):
                return candidate

    def is_prime_miller_rabin(self, n, k=10):
        """Miller-Rabin primality test"""
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        
        r = 0
        d = n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
                
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def generate_parameters(self, key_length=1024):
        """Generate public parameters (p, g)"""
        print("Génération des paramètres publics...")
        self.p = self.generate_random_prime(key_length)
        self.g = 2  # Simplified generator
        print(f"Paramètres générés avec succès!")
        
    def generate_private_key(self):
        """Generate private key"""
        if not self.p:
            raise ValueError("Les paramètres publics doivent être générés d'abord")
        
        self.private_key = random.randrange(2, self.p - 1)
        print("Clé privée générée avec succès!")
        
    def generate_public_key(self):
        """Generate public key from private key"""
        if not self.private_key or not self.p or not self.g:
            raise ValueError("Les paramètres et la clé privée doivent être générés d'abord")
            
        self.public_key = pow(self.g, self.private_key, self.p)
        print("Clé publique générée avec succès!")
        
    def compute_shared_secret(self, other_public_key):
        """Compute shared secret using other party's public key"""
        if not self.private_key or not self.p:
            raise ValueError("Clé privée et paramètres requis")
            
        self.shared_secret = pow(other_public_key, self.private_key, self.p)
        print("Secret partagé calculé avec succès!")
        
    def derive_session_key(self, key_length=32):
        """Derive session key from shared secret"""
        if not self.shared_secret:
            raise ValueError("Le secret partagé doit être calculé d'abord")
            
        secret_bytes = str(self.shared_secret).encode('utf-8')
        hash_digest = hashlib.sha256(secret_bytes).digest()
        self.session_key = hash_digest[:key_length]
        print("Clé de session dérivée avec succès!")


def print_banner():
    print("=" * 60)
    print("      ÉCHANGE DE CLÉS DIFFIE-HELLMAN INTERACTIF")
    print("=" * 60)
    print()


def get_user_input():
    """Interface utilisateur pour saisir les options"""
    print("Choisissez une option:")
    print("1. Générer les paramètres publics (p, g)")
    print("2. Générer votre paire de clés (privée/publique)")
    print("3. Calculer le secret partagé avec la clé publique de l'autre partie")
    print("4. Dériver une clé de session")
    print("5. Afficher vos informations actuelles")
    print("6. Simuler un échange complet entre deux parties")
    print("7. Chiffrer un message avec la clé de session (AES simulation)")
    print("8. Quitter")
    print()

    choice = input("Votre choix (1-8): ").strip()
    return choice


def generate_parameters(dh):
    """Interface pour générer les paramètres publics"""
    print("\n--- GÉNÉRATION DES PARAMÈTRES PUBLICS ---")
    
    print("Choisissez la taille de la clé:")
    print("1. 512 bits (rapide, pour démonstration)")
    print("2. 1024 bits (sécurité modérée)")
    print("3. 2048 bits (sécurité élevée, plus lent)")
    
    size_choice = input("Votre choix (1-3): ").strip()
    
    if size_choice == "1":
        key_length = 512
    elif size_choice == "2":
        key_length = 1024
    elif size_choice == "3":
        key_length = 2048
    else:
        print("Choix invalide.")
        return
    
    try:
        dh.generate_parameters(key_length)
        
        print("\n--- PARAMÈTRES GÉNÉRÉS ---")
        print(f"Prime p: {dh.p}")
        print(f"Générateur g: {dh.g}")
        print(f"Prime p (hex): {hex(dh.p)}")
        print("Ces paramètres peuvent être partagés publiquement.")
        
    except Exception as e:
        print(f"Erreur lors de la génération des paramètres: {e}")


def generate_key_pair(dh):
    """Interface pour générer la paire de clés"""
    print("\n--- GÉNÉRATION DE VOTRE PAIRE DE CLÉS ---")
    
    if not dh.p or not dh.g:
        print("Erreur: Les paramètres publics doivent être générés d'abord.")
        return
    
    try:
        dh.generate_private_key()
        dh.generate_public_key()
        
        print("\n--- CLÉS GÉNÉRÉES ---")
        print(f"Clé privée: {dh.private_key}")
        print(f"⚠️  GARDEZ CETTE CLÉ SECRÈTE!")
        print(f"Clé publique: {dh.public_key}")
        print(f"Clé publique (hex): {hex(dh.public_key)}")
        print(f"Clé publique (base64): {base64.b64encode(dh.public_key.to_bytes((dh.public_key.bit_length() + 7) // 8, 'big')).decode()}")
        print("✅ Vous pouvez partager votre clé publique en toute sécurité.")
        
    except Exception as e:
        print(f"Erreur lors de la génération des clés: {e}")


def compute_shared_secret(dh):
    """Interface pour calculer le secret partagé"""
    print("\n--- CALCUL DU SECRET PARTAGÉ ---")
    
    if not dh.private_key or not dh.p:
        print("Erreur: Vous devez d'abord générer vos clés.")
        return
    
    print("Format de la clé publique de l'autre partie:")
    print("1. Nombre décimal")
    print("2. Hexadécimal")
    print("3. Base64")
    
    format_choice = input("Votre choix (1-3): ").strip()
    other_public_input = input("Entrez la clé publique de l'autre partie: ").strip()
    
    try:
        if format_choice == "1":
            other_public_key = int(other_public_input)
        elif format_choice == "2":
            other_public_key = int(other_public_input, 16)
        elif format_choice == "3":
            decoded_bytes = base64.b64decode(other_public_input)
            other_public_key = int.from_bytes(decoded_bytes, 'big')
        else:
            print("Choix invalide.")
            return
            
        dh.compute_shared_secret(other_public_key)
        
        print("\n--- SECRET PARTAGÉ CALCULÉ ---")
        print(f"Secret partagé: {dh.shared_secret}")
        print(f"Secret partagé (hex): {hex(dh.shared_secret)}")
        print("🔐 Ce secret est maintenant connu des deux parties uniquement!")
        
    except Exception as e:
        print(f"Erreur lors du calcul du secret partagé: {e}")


def derive_session_key(dh):
    """Interface pour dériver une clé de session"""
    print("\n--- DÉRIVATION DE LA CLÉ DE SESSION ---")
    
    if not dh.shared_secret:
        print("Erreur: Le secret partagé doit être calculé d'abord.")
        return
    
    print("Choisissez la taille de la clé de session:")
    print("1. 16 bytes (128 bits) - Compatible AES-128")
    print("2. 24 bytes (192 bits) - Compatible AES-192")
    print("3. 32 bytes (256 bits) - Compatible AES-256")
    
    size_choice = input("Votre choix (1-3): ").strip()
    
    if size_choice == "1":
        key_length = 16
    elif size_choice == "2":
        key_length = 24
    elif size_choice == "3":
        key_length = 32
    else:
        print("Choix invalide.")
        return
    
    try:
        dh.derive_session_key(key_length)
        
        print("\n--- CLÉ DE SESSION DÉRIVÉE ---")
        print(f"Clé de session (hex): {dh.session_key.hex()}")
        print(f"Clé de session (base64): {base64.b64encode(dh.session_key).decode()}")
        print(f"Taille: {len(dh.session_key)} bytes ({len(dh.session_key) * 8} bits)")
        print("🔑 Cette clé peut maintenant être utilisée pour le chiffrement symétrique!")
        
    except Exception as e:
        print(f"Erreur lors de la dérivation de la clé: {e}")


def show_current_info(dh):
    """Affiche les informations actuelles"""
    print("\n--- VOS INFORMATIONS ACTUELLES ---")
    
    if dh.p and dh.g:
        print(f"Paramètres publics:")
        print(f"  Prime p: {dh.p}")
        print(f"  Générateur g: {dh.g}")
    else:
        print("Paramètres publics: Non générés")
    
    if dh.private_key:
        print(f"Clé privée: {dh.private_key} (SECRÈTE)")
    else:
        print("Clé privée: Non générée")
    
    if dh.public_key:
        print(f"Clé publique: {dh.public_key}")
        print(f"Clé publique (hex): {hex(dh.public_key)}")
    else:
        print("Clé publique: Non générée")
    
    if dh.shared_secret:
        print(f"Secret partagé: {dh.shared_secret}")
    else:
        print("Secret partagé: Non calculé")
    
    if dh.session_key:
        print(f"Clé de session: {dh.session_key.hex()}")
    else:
        print("Clé de session: Non dérivée")


def simulate_full_exchange():
    """Simule un échange complet entre deux parties"""
    print("\n--- SIMULATION D'UN ÉCHANGE COMPLET ---")
    
    # Création de deux instances DH
    alice = DiffieHellman()
    bob = DiffieHellman()
    
    print("Étape 1: Génération des paramètres publics...")
    alice.generate_parameters(1024)
    
    # Bob utilise les mêmes paramètres
    bob.p = alice.p
    bob.g = alice.g
    
    print("Étape 2: Alice génère sa paire de clés...")
    alice.generate_private_key()
    alice.generate_public_key()
    
    print("Étape 3: Bob génère sa paire de clés...")
    bob.generate_private_key()
    bob.generate_public_key()
    
    print("Étape 4: Échange des clés publiques...")
    print(f"Alice envoie sa clé publique à Bob: {alice.public_key}")
    print(f"Bob envoie sa clé publique à Alice: {bob.public_key}")
    
    print("Étape 5: Calcul des secrets partagés...")
    alice.compute_shared_secret(bob.public_key)
    bob.compute_shared_secret(alice.public_key)
    
    print("Étape 6: Vérification...")
    if alice.shared_secret == bob.shared_secret:
        print("✅ SUCCESS! Alice et Bob ont le même secret partagé!")
        print(f"Secret partagé: {alice.shared_secret}")
        
        print("Étape 7: Dérivation des clés de session...")
        alice.derive_session_key()
        bob.derive_session_key()
        
        if alice.session_key == bob.session_key:
            print("✅ SUCCESS! Les clés de session sont identiques!")
            print(f"Clé de session: {alice.session_key.hex()}")
        else:
            print("❌ ERREUR! Les clés de session diffèrent!")
    else:
        print("❌ ERREUR! Les secrets partagés diffèrent!")


def encrypt_message_simulation(dh):
    """Simulation de chiffrement avec la clé de session"""
    print("\n--- SIMULATION DE CHIFFREMENT ---")
    
    if not dh.session_key:
        print("Erreur: Une clé de session doit être dérivée d'abord.")
        return
    
    message = input("Entrez le message à chiffrer: ")
    if not message:
        print("Erreur: Le message ne peut pas être vide.")
        return
    
    # Simulation simple avec XOR (pas un vrai AES)
    message_bytes = message.encode('utf-8')
    
    # Étendre la clé si nécessaire
    key_extended = (dh.session_key * ((len(message_bytes) // len(dh.session_key)) + 1))[:len(message_bytes)]
    
    # Chiffrement XOR simple
    encrypted = bytes(a ^ b for a, b in zip(message_bytes, key_extended))
    
    print("\n--- RÉSULTATS DU CHIFFREMENT (SIMULATION) ---")
    print(f"Message original: {message}")
    print(f"Clé utilisée: {dh.session_key.hex()}")
    print(f"Message chiffré (hex): {encrypted.hex()}")
    print(f"Message chiffré (base64): {base64.b64encode(encrypted).decode()}")
    print("⚠️  Ceci est une simulation XOR simple, pas un vrai AES!")
    
    # Test de déchiffrement
    decrypted = bytes(a ^ b for a, b in zip(encrypted, key_extended))
    decrypted_message = decrypted.decode('utf-8')
    print(f"Vérification - Message déchiffré: {decrypted_message}")


def main():
    """Fonction principale"""
    dh = DiffieHellman()
    
    while True:
        print_banner()
        choice = get_user_input()
        
        if choice == "1":
            generate_parameters(dh)
        elif choice == "2":
            generate_key_pair(dh)
        elif choice == "3":
            compute_shared_secret(dh)
        elif choice == "4":
            derive_session_key(dh)
        elif choice == "5":
            show_current_info(dh)
        elif choice == "6":
            simulate_full_exchange()
        elif choice == "7":
            encrypt_message_simulation(dh)
        elif choice == "8":
            print("Au revoir!")
            break
        else:
            print("Choix invalide. Veuillez choisir entre 1 et 8.")
        
        input("\nAppuyez sur Entrée pour continuer...")
        print("\n" * 2)


if __name__ == "__main__":
    main()