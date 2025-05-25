import os
import base64
from binascii import hexlify, unhexlify


class AES:
    def __init__(self):
        # S-Box utilisée pour SubBytes
        self.s_box = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        ]

        # S-Box inverse pour InvSubBytes
        self.inv_s_box = [
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
        ]

        # Constantes pour Rcon (utilisées dans l'expansion de clé)
        self.rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

    def gmul(self, a, b):
        """Multiplication dans le corps de Galois GF(2^8)"""
        p = 0
        for i in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            if hi_bit_set:
                a ^= 0x1b  # polynôme irréductible x^8 + x^4 + x^3 + x + 1
            b >>= 1
        return p & 0xff

    def sub_bytes(self, state):
        """Substitution des bytes avec la S-Box"""
        for i in range(4):
            for j in range(4):
                state[i][j] = self.s_box[state[i][j]]

    def inv_sub_bytes(self, state):
        """Substitution inverse des bytes"""
        for i in range(4):
            for j in range(4):
                state[i][j] = self.inv_s_box[state[i][j]]

    def shift_rows(self, state):
        """Décalage des lignes"""
        # Ligne 0: pas de décalage
        # Ligne 1: décalage de 1 vers la gauche
        state[1] = state[1][1:] + state[1][:1]
        # Ligne 2: décalage de 2 vers la gauche
        state[2] = state[2][2:] + state[2][:2]
        # Ligne 3: décalage de 3 vers la gauche
        state[3] = state[3][3:] + state[3][:3]

    def inv_shift_rows(self, state):
        """Décalage inverse des lignes"""
        # Ligne 0: pas de décalage
        # Ligne 1: décalage de 1 vers la droite
        state[1] = state[1][-1:] + state[1][:-1]
        # Ligne 2: décalage de 2 vers la droite
        state[2] = state[2][-2:] + state[2][:-2]
        # Ligne 3: décalage de 3 vers la droite
        state[3] = state[3][-3:] + state[3][:-3]

    def mix_columns(self, state):
        """Mélange des colonnes"""
        for i in range(4):
            col = [state[j][i] for j in range(4)]
            state[0][i] = self.gmul(col[0], 2) ^ self.gmul(col[1], 3) ^ col[2] ^ col[3]
            state[1][i] = col[0] ^ self.gmul(col[1], 2) ^ self.gmul(col[2], 3) ^ col[3]
            state[2][i] = col[0] ^ col[1] ^ self.gmul(col[2], 2) ^ self.gmul(col[3], 3)
            state[3][i] = self.gmul(col[0], 3) ^ col[1] ^ col[2] ^ self.gmul(col[3], 2)

    def inv_mix_columns(self, state):
        """Mélange inverse des colonnes"""
        for i in range(4):
            col = [state[j][i] for j in range(4)]
            state[0][i] = self.gmul(col[0], 14) ^ self.gmul(col[1], 11) ^ self.gmul(col[2], 13) ^ self.gmul(col[3], 9)
            state[1][i] = self.gmul(col[0], 9) ^ self.gmul(col[1], 14) ^ self.gmul(col[2], 11) ^ self.gmul(col[3], 13)
            state[2][i] = self.gmul(col[0], 13) ^ self.gmul(col[1], 9) ^ self.gmul(col[2], 14) ^ self.gmul(col[3], 11)
            state[3][i] = self.gmul(col[0], 11) ^ self.gmul(col[1], 13) ^ self.gmul(col[2], 9) ^ self.gmul(col[3], 14)

    def add_round_key(self, state, round_key):
        """Addition de la clé de tour (XOR)"""
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_key[i][j]

    def key_expansion(self, key):
        """Expansion de la clé pour générer les clés de tour"""
        # Conversion de la clé en matrice 4x4
        key_matrix = []
        for i in range(4):
            key_matrix.append([key[4 * i + j] for j in range(4)])

        # Génération des clés de tour
        round_keys = [key_matrix]

        for round_num in range(10):
            prev_key = round_keys[-1]
            new_key = [[0 for _ in range(4)] for _ in range(4)]

            # Première colonne
            temp = [prev_key[j][3] for j in range(4)]
            # RotWord
            temp = temp[1:] + temp[:1]
            # SubWord
            temp = [self.s_box[b] for b in temp]
            # XOR avec Rcon
            temp[0] ^= self.rcon[round_num]

            for i in range(4):
                new_key[i][0] = prev_key[i][0] ^ temp[i]

            # Autres colonnes
            for j in range(1, 4):
                for i in range(4):
                    new_key[i][j] = prev_key[i][j] ^ new_key[i][j - 1]

            round_keys.append(new_key)

        return round_keys

    def encrypt_block(self, plaintext, key):
        """Chiffrement d'un bloc de 16 bytes"""
        # Conversion en matrice d'état 4x4
        state = []
        for i in range(4):
            state.append([plaintext[4 * i + j] for j in range(4)])

        # Expansion de la clé
        round_keys = self.key_expansion(key)

        # AddRoundKey initial
        self.add_round_key(state, round_keys[0])

        # 9 tours principaux
        for round_num in range(1, 10):
            self.sub_bytes(state)
            self.shift_rows(state)
            self.mix_columns(state)
            self.add_round_key(state, round_keys[round_num])

        # Tour final (sans MixColumns)
        self.sub_bytes(state)
        self.shift_rows(state)
        self.add_round_key(state, round_keys[10])

        # Conversion de retour en bytes
        result = []
        for i in range(4):
            for j in range(4):
                result.append(state[i][j])

        return bytes(result)

    def decrypt_block(self, ciphertext, key):
        """Déchiffrement d'un bloc de 16 bytes"""
        # Conversion en matrice d'état 4x4
        state = []
        for i in range(4):
            state.append([ciphertext[4 * i + j] for j in range(4)])

        # Expansion de la clé
        round_keys = self.key_expansion(key)

        # AddRoundKey initial (avec la dernière clé de tour)
        self.add_round_key(state, round_keys[10])

        # Tour initial inverse
        self.inv_shift_rows(state)
        self.inv_sub_bytes(state)

        # 9 tours principaux inverses
        for round_num in range(9, 0, -1):
            self.add_round_key(state, round_keys[round_num])
            self.inv_mix_columns(state)
            self.inv_shift_rows(state)
            self.inv_sub_bytes(state)

        # AddRoundKey final
        self.add_round_key(state, round_keys[0])

        # Conversion de retour en bytes
        result = []
        for i in range(4):
            for j in range(4):
                result.append(state[i][j])

        return bytes(result)

    def pad_data(self, data):
        """Padding PKCS7 pour les données"""
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def unpad_data(self, data):
        """Suppression du padding PKCS7"""
        padding_length = data[-1]
        return data[:-padding_length]

    def encrypt(self, plaintext, key):
        """Chiffrement complet avec padding"""
        if len(key) != 16:
            raise ValueError("La clé doit faire exactement 16 bytes (128 bits)")

        # Conversion en bytes si nécessaire
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        if isinstance(key, str):
            key = key.encode('utf-8')

        # Padding des données
        padded_data = self.pad_data(plaintext)

        # Chiffrement par blocs
        encrypted_blocks = []
        for i in range(0, len(padded_data), 16):
            block = padded_data[i:i + 16]
            encrypted_block = self.encrypt_block(block, key)
            encrypted_blocks.append(encrypted_block)

        return b''.join(encrypted_blocks)

    def decrypt(self, ciphertext, key):
        """Déchiffrement complet avec suppression du padding"""
        if len(key) != 16:
            raise ValueError("La clé doit faire exactement 16 bytes (128 bits)")

        # Conversion en bytes si nécessaire
        if isinstance(key, str):
            key = key.encode('utf-8')

        # Déchiffrement par blocs
        decrypted_blocks = []
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i + 16]
            decrypted_block = self.decrypt_block(block, key)
            decrypted_blocks.append(decrypted_block)

        decrypted_data = b''.join(decrypted_blocks)

        # Suppression du padding
        return self.unpad_data(decrypted_data)


def print_banner():
    print("=" * 60)
    print("          AES-128 ENCRYPTION/DECRYPTION TOOL")
    print("=" * 60)
    print()


def generate_random_key():
    """Génère une clé aléatoire de 16 bytes"""
    return os.urandom(16)


def get_user_input():
    """Interface utilisateur pour saisir les données"""
    print("Choisissez une option:")
    print("1. Chiffrer un message")
    print("2. Déchiffrer un message")
    print("3. Générer une clé aléatoire")
    print("4. Quitter")
    print()

    choice = input("Votre choix (1-4): ").strip()
    return choice


def encrypt_message(aes):
    """Interface pour chiffrer un message"""
    print("\n--- CHIFFREMENT ---")

    # Saisie du message
    message = input("Entrez le message à chiffrer: ")
    if not message:
        print("Erreur: Le message ne peut pas être vide.")
        return

    # Saisie de la clé
    print("\nOptions pour la clé:")
    print("1. Entrer une clé de 16 caractères")
    print("2. Générer une clé aléatoire")

    key_choice = input("Votre choix (1-2): ").strip()

    if key_choice == "1":
        key = input("Entrez la clé (exactement 16 caractères): ")
        if len(key) != 16:
            print(f"Erreur: La clé doit faire exactement 16 caractères. Longueur actuelle: {len(key)}")
            return
    elif key_choice == "2":
        key = generate_random_key()
        print(f"Clé générée (hex): {key.hex()}")
        print(f"Clé générée (base64): {base64.b64encode(key).decode()}")
    else:
        print("Choix invalide.")
        return

    try:
        # Chiffrement
        encrypted_data = aes.encrypt(message, key)

        # Affichage des résultats
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


def decrypt_message(aes):
    """Interface pour déchiffrer un message"""
    print("\n--- DÉCHIFFREMENT ---")

    # Saisie du message chiffré
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

    # Saisie de la clé
    print("\nFormat de la clé:")
    print("1. Texte (16 caractères)")
    print("2. Hexadécimal")
    print("3. Base64")

    key_format = input("Votre choix (1-3): ").strip()
    key_input = input("Entrez la clé: ").strip()

    try:
        if key_format == "1":
            if len(key_input) != 16:
                print(f"Erreur: La clé doit faire exactement 16 caractères. Longueur actuelle: {len(key_input)}")
                return
            key = key_input
        elif key_format == "2":
            key = bytes.fromhex(key_input)
            if len(key) != 16:
                print(f"Erreur: La clé doit faire exactement 16 bytes. Longueur actuelle: {len(key)}")
                return
        elif key_format == "3":
            key = base64.b64decode(key_input)
            if len(key) != 16:
                print(f"Erreur: La clé doit faire exactement 16 bytes. Longueur actuelle: {len(key)}")
                return
        else:
            print("Choix invalide.")
            return
    except Exception as e:
        print(f"Erreur lors de la conversion de la clé: {e}")
        return

    try:
        # Déchiffrement
        decrypted_data = aes.decrypt(encrypted_data, key)
        decrypted_message = decrypted_data.decode('utf-8')

        # Affichage des résultats
        print("\n--- RÉSULTATS DU DÉCHIFFREMENT ---")
        print(f"Message déchiffré: {decrypted_message}")

    except Exception as e:
        print(f"Erreur lors du déchiffrement: {e}")


def show_random_key():
    """Génère et affiche une clé aléatoire"""
    print("\n--- GÉNÉRATION DE CLÉ ALÉATOIRE ---")
    key = generate_random_key()
    print(f"Clé aléatoire générée:")
    print(f"  Hexadécimal: {key.hex()}")
    print(f"  Base64: {base64.b64encode(key).decode()}")
    print(f"  ASCII (si imprimable): {key.decode('utf-8', errors='replace')}")


def main_AES():
    """Fonction principale"""
    aes = AES()

    while True:
        print_banner()
        choice = get_user_input()

        if choice == "1":
            encrypt_message(aes)
        elif choice == "2":
            decrypt_message(aes)
        elif choice == "3":
            show_random_key()
        elif choice == "4":
            print("Au revoir!")
            break
        else:
            print("Choix invalide. Veuillez choisir entre 1 et 4.")

        input("\nAppuyez sur Entrée pour continuer...")
        print("\n" * 2)


