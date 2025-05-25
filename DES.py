# DES Algorithm - Interactive Implementation

import os
import base64
from binascii import hexlify, unhexlify

# Permutation Tables
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

P = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
]

S = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


class DES:
    def __init__(self):
        pass

    def hex_to_bin(self, hex_str):
        """Convert hexadecimal string to binary string"""
        return bin(int(hex_str, 16))[2:].zfill(len(hex_str) * 4)

    def bin_to_hex(self, bin_str):
        """Convert binary string to hexadecimal string"""
        return hex(int(bin_str, 2))[2:].upper().zfill(len(bin_str) // 4)

    def permute(self, data, table):
        """Apply permutation using given table"""
        return ''.join(data[i - 1] for i in table)

    def left_shift(self, data, shifts):
        """Perform left circular shift"""
        return data[shifts:] + data[:shifts]

    def xor(self, a, b):
        """XOR two binary strings"""
        return ''.join('0' if a[i] == b[i] else '1' for i in range(len(a)))

    def sbox_substitution(self, data):
        """Apply S-box substitution"""
        result = ''
        for i in range(8):
            block = data[i * 6:(i + 1) * 6]
            row = int(block[0] + block[5], 2)
            col = int(block[1:5], 2)
            val = S[i][row][col]
            result += format(val, '04b')
        return result

    def generate_keys(self, key):
        """Generate 16 round keys from main key"""
        # Convert key to binary
        key_bin = self.hex_to_bin(key)
        
        # Apply PC1 permutation
        key_56 = self.permute(key_bin, PC1)
        
        # Split into left and right halves
        left = key_56[:28]
        right = key_56[28:]
        
        round_keys = []
        
        for i in range(16):
            # Perform left shifts
            left = self.left_shift(left, SHIFTS[i])
            right = self.left_shift(right, SHIFTS[i])
            
            # Combine and apply PC2
            combined = left + right
            round_key = self.permute(combined, PC2)
            round_keys.append(round_key)
        
        return round_keys

    def f_function(self, right, key):
        """Feistel function"""
        # Expansion
        expanded = self.permute(right, E)
        
        # XOR with round key
        xor_result = self.xor(expanded, key)
        
        # S-box substitution
        substituted = self.sbox_substitution(xor_result)
        
        # Permutation
        result = self.permute(substituted, P)
        
        return result

    def des_round(self, left, right, key):
        """Single DES round"""
        new_right = self.xor(left, self.f_function(right, key))
        return right, new_right

    def des_encrypt_block(self, plaintext, key):
        """Encrypt a single 8-byte block using DES"""
        # Convert to binary
        plain_bin = self.hex_to_bin(plaintext)
        
        # Initial permutation
        permuted = self.permute(plain_bin, IP)
        
        # Split into left and right halves
        left = permuted[:32]
        right = permuted[32:]
        
        # Generate round keys
        round_keys = self.generate_keys(key)
        
        # 16 rounds of Feistel
        for i in range(16):
            left, right = self.des_round(left, right, round_keys[i])
        
        # Swap and combine
        combined = right + left
        
        # Final permutation
        ciphertext_bin = self.permute(combined, FP)
        
        # Convert to hex
        return self.bin_to_hex(ciphertext_bin)

    def des_decrypt_block(self, ciphertext, key):
        """Decrypt a single 8-byte block using DES"""
        # Convert to binary
        cipher_bin = self.hex_to_bin(ciphertext)
        
        # Initial permutation
        permuted = self.permute(cipher_bin, IP)
        
        # Split into left and right halves
        left = permuted[:32]
        right = permuted[32:]
        
        # Generate round keys (reverse order for decryption)
        round_keys = self.generate_keys(key)
        round_keys.reverse()
        
        # 16 rounds of Feistel
        for i in range(16):
            left, right = self.des_round(left, right, round_keys[i])
        
        # Swap and combine
        combined = right + left
        
        # Final permutation
        plaintext_bin = self.permute(combined, FP)
        
        # Convert to hex
        return self.bin_to_hex(plaintext_bin)

    def pad_data(self, data):
        """Padding PKCS7 for the data"""
        block_size = 8
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def unpad_data(self, data):
        """Remove PKCS7 padding"""
        padding_length = data[-1]
        return data[:-padding_length]

    def encrypt(self, plaintext, key):
        """Complete encryption with padding"""
        if len(key) != 8:
            raise ValueError("La clé doit faire exactement 8 bytes (64 bits)")

        # Convert to bytes if necessary
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        if isinstance(key, str):
            key = key.encode('utf-8')

        # Pad the data
        padded_data = self.pad_data(plaintext)

        # Convert key to hex
        key_hex = key.hex().upper()

        # Encrypt by blocks
        encrypted_blocks = []
        for i in range(0, len(padded_data), 8):
            block = padded_data[i:i + 8]
            block_hex = block.hex().upper()
            encrypted_block_hex = self.des_encrypt_block(block_hex, key_hex)
            encrypted_blocks.append(bytes.fromhex(encrypted_block_hex))

        return b''.join(encrypted_blocks)

    def decrypt(self, ciphertext, key):
        """Complete decryption with padding removal"""
        if len(key) != 8:
            raise ValueError("La clé doit faire exactement 8 bytes (64 bits)")

        # Convert to bytes if necessary
        if isinstance(key, str):
            key = key.encode('utf-8')

        # Convert key to hex
        key_hex = key.hex().upper()

        # Decrypt by blocks
        decrypted_blocks = []
        for i in range(0, len(ciphertext), 8):
            block = ciphertext[i:i + 8]
            block_hex = block.hex().upper()
            decrypted_block_hex = self.des_decrypt_block(block_hex, key_hex)
            decrypted_blocks.append(bytes.fromhex(decrypted_block_hex))

        decrypted_data = b''.join(decrypted_blocks)

        # Remove padding
        return self.unpad_data(decrypted_data)


def print_banner():
    print("=" * 60)
    print("          DES-64 ENCRYPTION/DECRYPTION TOOL")
    print("=" * 60)
    print()


def generate_random_key():
    """Generate a random 8-byte key"""
    return os.urandom(8)


def get_user_input():
    """User interface for input"""
    print("Choisissez une option:")
    print("1. Chiffrer un message")
    print("2. Déchiffrer un message")
    print("3. Générer une clé aléatoire")
    print("4. Quitter")
    print()

    choice = input("Votre choix (1-4): ").strip()
    return choice


def encrypt_message(des):
    """Interface for encrypting a message"""
    print("\n--- CHIFFREMENT ---")

    # Enter message
    message = input("Entrez le message à chiffrer: ")
    if not message:
        print("Erreur: Le message ne peut pas être vide.")
        return

    # Enter key
    print("\nOptions pour la clé:")
    print("1. Entrer une clé de 8 caractères")
    print("2. Générer une clé aléatoire")

    key_choice = input("Votre choix (1-2): ").strip()

    if key_choice == "1":
        key = input("Entrez la clé (exactement 8 caractères): ")
        if len(key) != 8:
            print(f"Erreur: La clé doit faire exactement 8 caractères. Longueur actuelle: {len(key)}")
            return
    elif key_choice == "2":
        key = generate_random_key()
        print(f"Clé générée (hex): {key.hex()}")
        print(f"Clé générée (base64): {base64.b64encode(key).decode()}")
    else:
        print("Choix invalide.")
        return

    try:
        # Encryption
        encrypted_data = des.encrypt(message, key)

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


def decrypt_message(des):
    """Interface for decrypting a message"""
    print("\n--- DÉCHIFFREMENT ---")

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
    print("1. Texte (8 caractères)")
    print("2. Hexadécimal")
    print("3. Base64")

    key_format = input("Votre choix (1-3): ").strip()
    key_input = input("Entrez la clé: ").strip()

    try:
        if key_format == "1":
            if len(key_input) != 8:
                print(f"Erreur: La clé doit faire exactement 8 caractères. Longueur actuelle: {len(key_input)}")
                return
            key = key_input
        elif key_format == "2":
            key = bytes.fromhex(key_input)
            if len(key) != 8:
                print(f"Erreur: La clé doit faire exactement 8 bytes. Longueur actuelle: {len(key)}")
                return
        elif key_format == "3":
            key = base64.b64decode(key_input)
            if len(key) != 8:
                print(f"Erreur: La clé doit faire exactement 8 bytes. Longueur actuelle: {len(key)}")
                return
        else:
            print("Choix invalide.")
            return
    except Exception as e:
        print(f"Erreur lors de la conversion de la clé: {e}")
        return

    try:
        # Decryption
        decrypted_data = des.decrypt(encrypted_data, key)
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
    print(f"Clé aléatoire générée:")
    print(f"  Hexadécimal: {key.hex()}")
    print(f"  Base64: {base64.b64encode(key).decode()}")
    print(f"  ASCII (si imprimable): {key.decode('utf-8', errors='replace')}")


def main_DES():
    """Main function"""
    des = DES()

    while True:
        print_banner()
        choice = get_user_input()

        if choice == "1":
            encrypt_message(des)
        elif choice == "2":
            decrypt_message(des)
        elif choice == "3":
            show_random_key()
        elif choice == "4":
            print("Au revoir!")
            break
        else:
            print("Choix invalide. Veuillez choisir entre 1 et 4.")

        input("\nAppuyez sur Entrée pour continuer...")
        print("\n" * 2)


