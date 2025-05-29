# Implementation complète des algorithmes de chiffrement
# Classification: Classiques, Symétriques, Asymétriques, Signatures Numériques

# Imports for existing modules
from AES import *
from DES import *
from RSA import *
from RC4 import *
from Diffie_Hellman import *
from ElGamal import *
from veginere import *
from kasiskiAndSomeFunction import *
from dechiffrement_cesar import *

# Imports for classical algorithms and signatures
import string
import numpy as np
import random
from math import gcd
from sympy import Matrix
import hashlib
import math


# ==================== DIGITAL SIGNATURE IMPLEMENTATION ====================

def is_prime(n, k=5):
    """Miller-Rabin primality test"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r = 0
    d = n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
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


def generate_prime(bits):
    """Generate a random prime number of specified bit length"""
    while True:
        num = random.getrandbits(bits)
        num |= (1 << bits - 1) | 1  # Ensure it's odd and has correct bit length
        if is_prime(num):
            return num


def extended_gcd(a, b):
    """Extended Euclidean Algorithm"""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def mod_inverse(e, phi):
    """Calculate modular multiplicative inverse"""
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return (x % phi + phi) % phi


def generate_rsa_keypair_signature(key_size=1024):
    """Generate RSA public and private key pair for signatures"""
    p = generate_prime(key_size // 2)
    q = generate_prime(key_size // 2)
    while p == q:
        q = generate_prime(key_size // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose e (commonly 65537)
    e = 65537
    while math.gcd(e, phi) != 1:
        e += 2

    # Calculate d (private exponent)
    d = mod_inverse(e, phi)

    # Public key: (e, n), Private key: (d, n)
    public_key = (e, n)
    private_key = (d, n)

    return public_key, private_key


def hash_message(message):
    """Create SHA-256 hash of the message"""
    if isinstance(message, str):
        message = message.encode('utf-8')
    return hashlib.sha256(message).digest()


def bytes_to_int(bytes_data):
    """Convert bytes to integer"""
    return int.from_bytes(bytes_data, byteorder='big')


def int_to_bytes(num, length):
    """Convert integer to bytes"""
    return num.to_bytes(length, byteorder='big')


def sign_message(message, private_key):
    """Create a digital signature for the message"""
    # Hash the message
    message_hash = hash_message(message)
    hash_int = bytes_to_int(message_hash)

    # Sign with private key (d, n)
    d, n = private_key
    signature_int = pow(hash_int, d, n)

    # Convert back to bytes
    byte_length = (n.bit_length() + 7) // 8
    signature = int_to_bytes(signature_int, byte_length)

    return signature


def verify_signature(message, signature, public_key):
    """Verify a digital signature"""
    try:
        # Hash the message
        message_hash = hash_message(message)
        hash_int = bytes_to_int(message_hash)

        # Convert signature to integer
        signature_int = bytes_to_int(signature)

        # Verify with public key (e, n)
        e, n = public_key
        decrypted_hash_int = pow(signature_int, e, n)

        # Compare hashes
        return hash_int == decrypted_hash_int

    except Exception:
        return False


def export_key_info(public_key, private_key):
    """Export keys in a readable format"""
    e, n = public_key
    d, _ = private_key

    return {
        'public_key': {
            'e': e,
            'n': n
        },
        'private_key': {
            'd': d,
            'n': n
        },
        'key_size_bits': n.bit_length()
    }


def create_signature_system(key_size=1024):
    """Convenience function to create a complete signature system"""
    public_key, private_key = generate_rsa_keypair_signature(key_size)

    def sign(message):
        return sign_message(message, private_key)

    def verify(message, signature):
        return verify_signature(message, signature, public_key)

    def get_public_key():
        return public_key

    def get_key_info():
        return export_key_info(public_key, private_key)

    return {
        'sign': sign,
        'verify': verify,
        'get_public_key': get_public_key,
        'get_key_info': get_key_info,
        'public_key': public_key,
        'private_key': private_key
    }


def sign_multiple_messages(messages, private_key):
    """Sign multiple messages at once"""
    signatures = []
    for msg in messages:
        sig = sign_message(msg, private_key)
        signatures.append(sig)
    return signatures


def verify_multiple_signatures(messages, signatures, public_key):
    """Verify multiple message-signature pairs"""
    results = []
    for msg, sig in zip(messages, signatures):
        valid = verify_signature(msg, sig, public_key)
        results.append(valid)
    return results


def create_message_signature_pair(message, private_key):
    """Create a message-signature pair for easy transmission"""
    signature = sign_message(message, private_key)
    return {
        'message': message,
        'signature': signature.hex(),  # Hex for easy transmission
        'signature_bytes': signature
    }


def verify_message_signature_pair(pair, public_key):
    """Verify a message-signature pair"""
    message = pair['message']
    signature_bytes = pair['signature_bytes']
    return verify_signature(message, signature_bytes, public_key)


# ==================== SIGNATURE MENU FUNCTIONS ====================

def main_signatures():
    """Main menu for digital signatures"""
    # Store key pairs globally for the session
    global current_keys
    current_keys = None

    while True:
        print("\n" + "-" * 50)
        print(" 🔏 SIGNATURES NUMÉRIQUES RSA")
        print("-" * 50)
        print("1. Générer une paire de clés")
        print("2. Signer un message")
        print("3. Vérifier une signature")
        print("4. Démonstration complète")
        print("5. Signer plusieurs messages")
        print("6. Test d'intégrité (message modifié)")
        print("7. Afficher les informations des clés")
        print("0. Retour au menu principal")
        print("-" * 50)

        choice = input("\nEntrez votre choix (0-7): ")

        if choice == '1':
            generate_keys_menu()
        elif choice == '2':
            sign_message_menu()
        elif choice == '3':
            verify_signature_menu()
        elif choice == '4':
            demo_complete_signature()
        elif choice == '5':
            sign_multiple_menu()
        elif choice == '6':
            test_integrity_menu()
        elif choice == '7':
            display_key_info()
        elif choice == '0':
            break
        else:
            print("❌ Choix invalide, veuillez réessayer.")


def generate_keys_menu():
    """Generate RSA key pair for signatures"""
    global current_keys

    print("\n🔑 Génération de paires de clés RSA")
    print("Tailles de clés disponibles:")
    print("1. 512 bits (rapide, démo)")
    print("2. 1024 bits (standard)")
    print("3. 2048 bits (haute sécurité)")

    size_choice = input("Choisissez la taille (1-3): ")

    key_sizes = {'1': 512, '2': 1024, '3': 2048}
    key_size = key_sizes.get(size_choice, 1024)

    print(f"\n⏳ Génération des clés {key_size} bits en cours...")
    public_key, private_key = generate_rsa_keypair_signature(key_size)

    current_keys = {
        'public': public_key,
        'private': private_key,
        'size': key_size
    }

    print("✅ Paire de clés générée avec succès!")
    print(f"🔑 Clé publique (e, n): ({public_key[0]}, {str(public_key[1])[:20]}...)")
    print(f"🔐 Clé privée générée (taille: {key_size} bits)")


def sign_message_menu():
    """Sign a message"""
    global current_keys

    if current_keys is None:
        print("❌ Aucune paire de clés générée. Générez d'abord une paire de clés.")
        return

    print("\n✍️  Signature de message")
    message = input("Entrez le message à signer: ")

    if not message.strip():
        print("❌ Message vide, abandon.")
        return

    print("⏳ Signature en cours...")
    signature = sign_message(message, current_keys['private'])

    print("✅ Message signé avec succès!")
    print(f"📝 Message original: '{message}'")
    print(f"🔏 Signature (hex): {signature.hex()}")
    print(f"📊 Taille de la signature: {len(signature)} bytes")

    # Store for potential verification
    current_keys['last_message'] = message
    current_keys['last_signature'] = signature


def verify_signature_menu():
    """Verify a signature"""
    global current_keys

    if current_keys is None:
        print("❌ Aucune paire de clés générée. Générez d'abord une paire de clés.")
        return

    print("\n🔍 Vérification de signature")
    print("1. Vérifier le dernier message signé")
    print("2. Saisir manuellement message et signature")

    choice = input("Votre choix (1-2): ")

    if choice == '1':
        if 'last_message' not in current_keys:
            print("❌ Aucun message précédemment signé.")
            return

        message = current_keys['last_message']
        signature = current_keys['last_signature']
        print(f"📝 Message: '{message}'")

    elif choice == '2':
        message = input("Entrez le message original: ")
        signature_hex = input("Entrez la signature (format hexadécimal): ")

        try:
            signature = bytes.fromhex(signature_hex)
        except ValueError:
            print("❌ Format de signature invalide.")
            return
    else:
        print("❌ Choix invalide.")
        return

    print("⏳ Vérification en cours...")
    is_valid = verify_signature(message, signature, current_keys['public'])

    if is_valid:
        print("✅ Signature VALIDE - Le message est authentique et intègre!")
    else:
        print("❌ Signature INVALIDE - Le message a été modifié ou la signature est incorrecte!")


def demo_complete_signature():
    """Complete demonstration of digital signatures"""
    print("\n🎯 Démonstration complète des signatures numériques")
    print("=" * 60)

    # Generate keys
    print("📋 1. Génération de la paire de clés RSA (512 bits)...")
    public_key, private_key = generate_rsa_keypair_signature(512)

    # Test message
    message = "Ceci est un message sécurisé avec signature numérique!"
    print(f"📝 2. Message original: '{message}'")

    # Sign the message
    print("\n✍️  3. Signature du message...")
    signature = sign_message(message, private_key)
    print(f"🔏 Signature générée (taille: {len(signature)} bytes)")

    # Verify the signature
    print("\n🔍 4. Vérification de la signature...")
    is_valid = verify_signature(message, signature, public_key)
    print(f"✅ Signature {'VALIDE' if is_valid else 'INVALIDE'}")

    # Test with tampered message
    print("\n🚨 5. Test avec un message modifié...")
    tampered_message = "Ceci est un message MODIFIÉ avec signature numérique!"
    is_valid_tampered = verify_signature(tampered_message, signature, public_key)
    print(f"📝 Message modifié: '{tampered_message}'")
    print(f"❌ Signature sur message modifié: {'VALIDE' if is_valid_tampered else 'INVALIDE'}")

    # Key information
    print("\n🔑 6. Informations sur les clés:")
    key_info = export_key_info(public_key, private_key)
    print(f"   • Taille des clés: {key_info['key_size_bits']} bits")
    print(f"   • Exposant public (e): {key_info['public_key']['e']}")
    print(f"   • Module (n): {str(key_info['public_key']['n'])[:30]}...")

    print("\n🎉 Démonstration terminée!")


def sign_multiple_menu():
    """Sign multiple messages"""
    global current_keys

    if current_keys is None:
        print("❌ Aucune paire de clés générée. Générez d'abord une paire de clés.")
        return

    print("\n📝 Signature de plusieurs messages")
    messages = []

    print("Entrez les messages à signer (ligne vide pour terminer):")
    i = 1
    while True:
        message = input(f"Message {i}: ")
        if not message.strip():
            break
        messages.append(message)
        i += 1

    if not messages:
        print("❌ Aucun message saisi.")
        return

    print(f"\n⏳ Signature de {len(messages)} messages...")
    signatures = sign_multiple_messages(messages, current_keys['private'])

    print("✅ Tous les messages ont été signés!")

    # Verify all signatures
    print("\n🔍 Vérification automatique de toutes les signatures...")
    results = verify_multiple_signatures(messages, signatures, current_keys['public'])

    for i, (msg, result) in enumerate(zip(messages, results)):
        status = "✅ VALIDE" if result else "❌ INVALIDE"
        print(f"Message {i + 1}: {status}")
        print(f"  Contenu: '{msg[:50]}{'...' if len(msg) > 50 else ''}'")


def test_integrity_menu():
    """Test message integrity by modifying message"""
    global current_keys

    if current_keys is None:
        print("❌ Aucune paire de clés générée. Générez d'abord une paire de clés.")
        return

    print("\n🧪 Test d'intégrité - Détection de modifications")

    original_message = input("Entrez le message original: ")
    if not original_message.strip():
        print("❌ Message vide.")
        return

    # Sign original message
    print("⏳ Signature du message original...")
    signature = sign_message(original_message, current_keys['private'])
    print("✅ Message signé!")

    # Verify original
    is_valid_original = verify_signature(original_message, signature, current_keys['public'])
    print(f"🔍 Vérification message original: {'✅ VALIDE' if is_valid_original else '❌ INVALIDE'}")

    # Test modified message
    print(f"\nMessage original: '{original_message}'")
    modified_message = input("Entrez une version modifiée du message: ")

    if modified_message == original_message:
        print("⚠️  Les messages sont identiques!")
        return

    # Verify modified message with same signature
    is_valid_modified = verify_signature(modified_message, signature, current_keys['public'])
    print(f"\n🚨 Test avec message modifié:")
    print(f"Message modifié: '{modified_message}'")
    print(f"Vérification: {'✅ VALIDE' if is_valid_modified else '❌ INVALIDE (comme attendu)'}")

    if not is_valid_modified:
        print("\n🎯 CONCLUSION: La signature a détecté la modification du message!")
        print("   L'intégrité du message est garantie par la signature numérique.")
    else:
        print("\n⚠️  ATTENTION: Ceci ne devrait pas arriver - problème de sécurité!")


def display_key_info():
    """Display current key information"""
    global current_keys

    if current_keys is None:
        print("❌ Aucune paire de clés générée.")
        return

    print("\n🔑 Informations sur les clés actuelles")
    print("=" * 40)

    key_info = export_key_info(current_keys['public'], current_keys['private'])

    print(f"📊 Taille des clés: {key_info['key_size_bits']} bits")
    print(f"🔓 Clé publique:")
    print(f"   • Exposant (e): {key_info['public_key']['e']}")
    print(f"   • Module (n): {str(key_info['public_key']['n'])[:50]}...")
    print(f"🔐 Clé privée:")
    print(f"   • Exposant (d): {str(key_info['private_key']['d'])[:50]}...")
    print(f"   • Module (n): {str(key_info['private_key']['n'])[:50]}...")

    if 'last_message' in current_keys:
        print(
            f"\n📝 Dernier message signé: '{current_keys['last_message'][:30]}{'...' if len(current_keys['last_message']) > 30 else ''}'")


# ==================== ALGORITHMES CLASSIQUES ====================

# César Cipher
def cesar_encrypt(text, shift):
    encrypted = ""
    for c in text:
        if c.isalpha():
            ascii_offset = 65 if c.isupper() else 97
            encrypted_char = chr((ord(c) - ascii_offset + shift) % 26 + ascii_offset)
            encrypted += encrypted_char
        else:
            encrypted += c
    return encrypted


def cesar_decrypt(text, shift):
    decrypted = ""
    for c in text:
        if c.isalpha():
            ascii_offset = 65 if c.isupper() else 97
            decrypted_char = chr((ord(c) - ascii_offset - shift) % 26 + ascii_offset)
            decrypted += decrypted_char
        else:
            decrypted += c
    return decrypted


def main_cesar_classique():
    while True:
        print("\n=== Chiffre de César ===")
        print("1. Chiffrer un message")
        print("2. Déchiffrer un message")
        print("3. Chiffrer et déchiffrer avec décalage aléatoire")
        print("4. Retour au menu principal")

        choice = input("\nEntrez votre choix (1-4): ")

        if choice == '1':
            message = input("Entrez le message à chiffrer: ")
            shift = int(input("Entrez la valeur de décalage (1-25): "))
            encrypted = cesar_encrypt(message, shift)
            print(f"\nMessage chiffré: {encrypted}")

        elif choice == '2':
            message = input("Entrez le message à déchiffrer: ")
            shift = int(input("Entrez la valeur de décalage (1-25): "))
            decrypted = cesar_decrypt(message, shift)
            print(f"\nMessage déchiffré: {decrypted}")

        elif choice == '3':
            message = input("Entrez le message à chiffrer: ")
            shift = random.randint(1, 25)
            encrypted = cesar_encrypt(message, shift)
            decrypted = cesar_decrypt(encrypted, shift)
            print(f"\nMessage chiffré: {encrypted}")
            print(f"Message déchiffré: {decrypted}")
            print(f"Décalage aléatoire utilisé: {shift}")

        elif choice == '4':
            break
        else:
            print("Choix invalide. Veuillez réessayer.")


# Affine Cipher
def affine_encrypt(text, a, b):
    if gcd(26, a) != 1:
        raise ValueError("'a' doit être premier avec 26, veuillez choisir un autre paramètre 'a'")
    else:
        text = text.upper()
        encrypted_text = ""
        alphabet = string.ascii_uppercase
        for char in text:
            if char in alphabet:
                x = alphabet.index(char)
                encrypted_char = alphabet[(a * x + b) % 26]
                encrypted_text += encrypted_char
            else:
                encrypted_text += char
        return encrypted_text


def find_inverse(a):
    for i in range(1, 26):
        if a * i % 26 == 1:
            return i


def affine_decrypt(crypted_text, a, b):
    if gcd(26, a) != 1:
        raise ValueError("'a' doit être premier avec 26, veuillez choisir un autre paramètre 'a'")
    else:
        crypted_text = crypted_text.upper()
        alphabet = string.ascii_uppercase
        decrypted_text = ""
        inv_a = find_inverse(a)
        for char in crypted_text:
            if char in alphabet:
                y = alphabet.index(char)
                decrypted_text += alphabet[inv_a * (y - b) % 26]
            else:
                decrypted_text += char
        return decrypted_text


def main_affine():
    print("\n=== Chiffre Affine ===")
    try:
        text = input("Entrez le texte: ")
        a = int(input("Entrez la valeur de 'a' (doit être premier avec 26): "))
        b = int(input("Entrez la valeur de 'b': "))

        crypted = affine_encrypt(text, a, b)
        print("Texte chiffré:", crypted)

        decrypted = affine_decrypt(crypted, a, b)
        print("Texte déchiffré:", decrypted)
    except ValueError as e:
        print(f"Erreur: {e}")


# Hill Cipher
def text_to_numbers(text):
    alphabet = string.ascii_uppercase
    return [alphabet.index(char) for char in text.upper() if char in alphabet]


def numbers_to_text(numbers):
    alphabet = string.ascii_uppercase
    return ''.join(alphabet[num] for num in numbers)


def hill_encrypt(text, key_matrix):
    text = text.upper().replace(" ", "")
    if len(text) % 2 != 0:
        text += 'X'

    text_numbers = text_to_numbers(text)
    encrypted_numbers = []

    for i in range(0, len(text_numbers), 2):
        pair = np.array([[text_numbers[i]], [text_numbers[i + 1]]])
        encrypted_pair = np.dot(key_matrix, pair) % 26
        encrypted_numbers.extend(encrypted_pair.flatten())

    return numbers_to_text(encrypted_numbers)


def hill_decrypt(ciphertext, key_matrix):
    ciphertext = ciphertext.upper().replace(" ", "")

    key_matrix_inv = Matrix(key_matrix).inv_mod(26)
    key_matrix_inv = np.array(key_matrix_inv).astype(int)

    cipher_numbers = text_to_numbers(ciphertext)
    decrypted_numbers = []

    for i in range(0, len(cipher_numbers), 2):
        pair = np.array([[cipher_numbers[i]], [cipher_numbers[i + 1]]])
        decrypted_pair = np.dot(key_matrix_inv, pair) % 26
        decrypted_numbers.extend(decrypted_pair.flatten())

    return numbers_to_text(decrypted_numbers)


def main_hill():
    print("\n=== Chiffre de Hill ===")
    try:
        message = input("Entrez le message: ")
        print("Entrez la matrice clé 2x2:")
        a = int(input("Entrez l'élément [0,0]: "))
        b = int(input("Entrez l'élément [0,1]: "))
        c = int(input("Entrez l'élément [1,0]: "))
        d = int(input("Entrez l'élément [1,1]: "))

        key_matrix = np.array([[a, b], [c, d]])

        cipher = hill_encrypt(message, key_matrix)
        print("Texte chiffré:", cipher)

        decrypted = hill_decrypt(cipher, key_matrix)
        print("Texte déchiffré:", decrypted)
    except Exception as e:
        print(f"Erreur: {e}")


# Playfair Cipher
def generate_playfair_matrix(key):
    key = key.upper().replace("J", "I")
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    matrix = ""

    for char in key + alphabet:
        if char not in matrix:
            matrix += char

    return [list(matrix[i:i + 5]) for i in range(0, 25, 5)]


def playfair_encrypt(text, key):
    matrix = generate_playfair_matrix(key)
    text = text.upper().replace("J", "I").replace(" ", "")

    pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i + 1] if i + 1 < len(text) else 'X'
        if a == b:
            b = 'X'
            i += 1
        else:
            i += 2
        pairs.append((a, b))

    encrypted_text = ""

    for a, b in pairs:
        ax, ay = next((r, c) for r, row in enumerate(matrix) for c, char in enumerate(row) if char == a)
        bx, by = next((r, c) for r, row in enumerate(matrix) for c, char in enumerate(row) if char == b)

        if ax == bx:
            encrypted_text += matrix[ax][(ay + 1) % 5] + matrix[bx][(by + 1) % 5]
        elif ay == by:
            encrypted_text += matrix[(ax + 1) % 5][ay] + matrix[(bx + 1) % 5][by]
        else:
            encrypted_text += matrix[ax][by] + matrix[bx][ay]

    return encrypted_text


def playfair_decrypt(ciphertext, key):
    matrix = generate_playfair_matrix(key)
    pairs = [(ciphertext[i], ciphertext[i + 1]) for i in range(0, len(ciphertext), 2)]
    decrypted_text = ""

    for a, b in pairs:
        ax, ay = next((r, c) for r, row in enumerate(matrix) for c, char in enumerate(row) if char == a)
        bx, by = next((r, c) for r, row in enumerate(matrix) for c, char in enumerate(row) if char == b)

        if ax == bx:
            decrypted_text += matrix[ax][(ay - 1) % 5] + matrix[bx][(by - 1) % 5]
        elif ay == by:
            decrypted_text += matrix[(ax - 1) % 5][ay] + matrix[(bx - 1) % 5][by]
        else:
            decrypted_text += matrix[ax][by] + matrix[bx][ay]

    return decrypted_text


def main_playfair():
    print("\n=== Chiffre de Playfair ===")
    key = input("Entrez la clé: ")
    message = input("Entrez le message: ")

    cipher = playfair_encrypt(message, key)
    print("Texte chiffré (Playfair):", cipher)

    decrypted = playfair_decrypt(cipher, key)
    print("Texte déchiffré (Playfair):", decrypted)


# Vigenère Cipher (fonction de déchiffrement améliorée)
def vigenere_encrypt(text, key):
    """Chiffre un texte avec le chiffre de Vigenère."""
    texte_chiffre = ""
    key_index = 0
    key = key.lower()

    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('a')
            if char.isupper():
                base = ord('A')
                texte_chiffre += chr((ord(char) - base + shift) % 26 + base)
            else:
                base = ord('a')
                texte_chiffre += chr((ord(char) - base + shift) % 26 + base)
            key_index += 1
        else:
            texte_chiffre += char
    return texte_chiffre


def main_vigenere_classique():
    print("\n=== Chiffre de Vigenère ===")
    print("1. Chiffrer")
    print("2. Déchiffrer")
    choice = input("Votre choix: ")

    if choice == '1':
        text = input("Entrez le texte à chiffrer: ")
        key = input("Entrez la clé: ")
        result = vigenere_encrypt(text, key)
        print("Texte chiffré:", result)
    elif choice == '2':
        ciphertext = input("Entrez le texte chiffré: ")
        key = input("Entrez la clé: ")
        result = vigenere_decrypt(ciphertext, key)
        print("Texte déchiffré:", result)


# ==================== MENU PRINCIPAL ====================

def main():
    print("=" * 60)
    print(" PROGRAMME DE CHIFFREMENT ET DÉCHIFFREMENT COMPLET")
    print("=" * 60)
    print()

    while True:
        print("\n" + "=" * 40)
        print(" CHOISISSEZ UNE CATÉGORIE:")
        print("=" * 40)
        print("1. 📜 ALGORITHMES CLASSIQUES")
        print("2. 🔐 ALGORITHMES SYMÉTRIQUES")
        print("3. 🔑 ALGORITHMES ASYMÉTRIQUES")
        print("4. 🔏 SIGNATURES NUMÉRIQUES")
        print("5. 🔍 OUTILS D'ANALYSE")
        print("0. ❌ QUITTER")
        print("=" * 40)

        category = input("\nEntrez votre choix (0-5): ")

        if category == '1':
            menu_classiques()
        elif category == '2':
            menu_symetriques()
        elif category == '3':
            menu_asymetriques()
        elif category == '4':
            main_signatures()
        elif category == '5':
            menu_outils()
        elif category == '0':
            print("\n🎉 Merci d'avoir utilisé le programme. Au revoir!")
            break
        else:
            print("❌ Choix invalide, veuillez réessayer.")


def menu_classiques():
    while True:
        print("\n" + "-" * 40)
        print(" 📜 ALGORITHMES CLASSIQUES")
        print("-" * 40)
        print("1. César")
        print("2. Affine")
        print("3. Hill")
        print("4. Playfair")
        print("5. Vigenère")
        print("0. Retour au menu principal")
        print("-" * 40)

        choice = input("\nEntrez votre choix (0-5): ")

        if choice == '1':
            main_cesar_classique()
        elif choice == '2':
            main_affine()
        elif choice == '3':
            main_hill()
        elif choice == '4':
            main_playfair()
        elif choice == '5':
            main_vigenere_classique()
        elif choice == '0':
            break
        else:
            print("❌ Choix invalide, veuillez réessayer.")


def menu_symetriques():
    while True:
        print("\n" + "-" * 40)
        print(" 🔐 ALGORITHMES SYMÉTRIQUES")
        print("-" * 40)
        print("1. RC4")
        print("2. AES")
        print("3. DES")
        print("0. Retour au menu principal")
        print("-" * 40)

        choice = input("\nEntrez votre choix (0-3): ")

        if choice == '1':
            main_RC4()
        elif choice == '2':
            main_AES()
        elif choice == '3':
            main_DES()
        elif choice == '0':
            break
        else:
            print("❌ Choix invalide, veuillez réessayer.")


def menu_asymetriques():
    while True:
        print("\n" + "-" * 40)
        print(" 🔑 ALGORITHMES ASYMÉTRIQUES")
        print("-" * 40)
        print("1. RSA")
        print("2. Diffie-Hellman")
        print("3. ElGamal")
        print("0. Retour au menu principal")
        print("-" * 40)

        choice = input("\nEntrez votre choix (0-3): ")

        if choice == '1':
            main_RSA()
        elif choice == '2':
            main_DiffieHellman()
        elif choice == '3':
            main_elgamal()
        elif choice == '0':
            break
        else:
            print("❌ Choix invalide, veuillez réessayer.")


def menu_outils():
    while True:
        print("\n" + "-" * 40)
        print(" 🔍 OUTILS D'ANALYSE")
        print("-" * 40)
        print("1. Vigenère (analyse complète)")
        print("2. Kasiski et autres fonctions")
        print("3. Déchiffrement César (force brute)")
        print("0. Retour au menu principal")
        print("-" * 40)

        choice = input("\nEntrez votre choix (0-3): ")

        if choice == '1':
            main_vigenere()
        elif choice == '2':
            kasiski_main()
        elif choice == '3':
            main_cesar()
        elif choice == '0':
            break
        else:
            print("❌ Choix invalide, veuillez réessayer.")


# ==================== INFORMATIONS SUR LES ALGORITHMES ====================

def afficher_info_algorithmes():
    print("\n" + "=" * 60)
    print(" CLASSIFICATION DES ALGORITHMES DE CHIFFREMENT")
    print("=" * 60)

    print("\n📜 ALGORITHMES CLASSIQUES (Substitution/Transposition):")
    print("   • César : Substitution monoalphabétique par décalage")
    print("   • Affine : Substitution monoalphabétique linéaire")
    print("   • Hill : Substitution par blocs utilisant des matrices")
    print("   • Playfair : Substitution par paires de lettres")
    print("   • Vigenère : Substitution polyalphabétique")

    print("\n🔐 ALGORITHMES SYMÉTRIQUES (Clé secrète partagée):")
    print("   • RC4 : Chiffrement par flot")
    print("   • AES : Standard de chiffrement avancé (blocs)")
    print("   • DES : Standard de chiffrement de données (blocs)")

    print("\n🔑 ALGORITHMES ASYMÉTRIQUES (Clé publique/privée):")
    print("   • RSA : Basé sur la factorisation de grands nombres")
    print("   • Diffie-Hellman : Échange de clés sécurisé")
    print("   • ElGamal : Basé sur le logarithme discret")

    print("\n🔏 SIGNATURES NUMÉRIQUES (Authentification et intégrité):")
    print("   • Signature RSA : Garantit l'authenticité et l'intégrité")
    print("   • Fonction de hachage SHA-256 : Empreinte unique du message")
    print("   • Vérification : Détection automatique des modifications")
    print("   • Non-répudiation : L'expéditeur ne peut nier avoir signé")

    print("\n🔍 OUTILS D'ANALYSE:")
    print("   • Analyse de Kasiski : Cryptanalyse de Vigenère")
    print("   • Force brute César : Test de tous les décalages")
    print("   • Analyse de fréquence : Détection de motifs")

    print("\n" + "=" * 60)
    print(" AVANTAGES DES SIGNATURES NUMÉRIQUES")
    print("=" * 60)
    print("✅ Authentification : Confirme l'identité de l'expéditeur")
    print("✅ Intégrité : Détecte toute modification du message")
    print("✅ Non-répudiation : L'expéditeur ne peut nier la signature")
    print("✅ Horodatage : Peut inclure la date/heure de signature")
    print("✅ Efficacité : Plus rapide que le chiffrement complet")

    print("\n" + "=" * 60)
    print(" APPLICATIONS PRATIQUES")
    print("=" * 60)
    print("📧 Emails sécurisés (PGP/GPG)")
    print("🏦 Transactions bancaires électroniques")
    print("📜 Documents juridiques numériques")
    print("💻 Mises à jour logicielles authentifiées")
    print("🌐 Certificats SSL/TLS pour sites web")
    print("🎫 Billets électroniques et QR codes")


if __name__ == "__main__":
    # Afficher les informations sur les algorithmes au démarrage
    afficher_info_algorithmes()

    # Lancer le menu principal
    main()