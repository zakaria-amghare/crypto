#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import string

class VigenereCipher:
    def __init__(self):
        pass

    def chiffrer_vigenere(self, plaintext, key):
        """
        Chiffre un texte avec le chiffre de Vigenère.
        
        Paramètres :
          - plaintext : le texte en clair (chaîne de caractères)
          - key : la clé utilisée pour le chiffrement (chaîne de caractères)
        
        Retourne :
          - Le texte chiffré.
        """
        texte_chiffre = ""
        key_index = 0
        key = key.lower()  # On passe la clé en minuscules pour simplifier

        for char in plaintext:
            if char.isalpha():
                # Calcul du décalage à partir de la clé (entre 0 et 25)
                shift = ord(key[key_index % len(key)]) - ord('a')
                if char.isupper():
                    base = ord('A')
                    # Chiffrement en tenant compte de la boucle de l'alphabet
                    texte_chiffre += chr((ord(char) - base + shift) % 26 + base)
                else:
                    base = ord('a')
                    texte_chiffre += chr((ord(char) - base + shift) % 26 + base)
                key_index += 1  # On passe à la lettre suivante de la clé
            else:
                # Si le caractère n'est pas une lettre, on le conserve
                texte_chiffre += char
        return texte_chiffre

    def dechiffrer_vigenere(self, ciphertext, key):
        """
        Déchiffre un texte chiffré avec le chiffre de Vigenère.
        
        Paramètres :
          - ciphertext : le texte chiffré (chaîne de caractères)
          - key : la clé utilisée pour le chiffrement (chaîne de caractères)
        
        Retourne :
          - Le texte déchiffré.
        """
        texte_clair = ""
        key_index = 0
        key = key.lower()  # On passe la clé en minuscules pour simplifier

        for char in ciphertext:
            if char.isalpha():
                # Calcul du décalage à partir de la clé (entre 0 et 25)
                shift = ord(key[key_index % len(key)]) - ord('a')
                if char.isupper():
                    base = ord('A')
                    # Déchiffrement en tenant compte de la boucle de l'alphabet
                    texte_clair += chr((ord(char) - base - shift) % 26 + base)
                else:
                    base = ord('a')
                    texte_clair += chr((ord(char) - base - shift) % 26 + base)
                key_index += 1  # On passe à la lettre suivante de la clé
            else:
                # Si le caractère n'est pas une lettre, on le conserve
                texte_clair += char
        return texte_clair


def print_banner():
    print("=" * 60)
    print("           CHIFFRE DE VIGENÈRE - OUTIL COMPLET")
    print("=" * 60)
    print()


def get_user_input():
    """Interface utilisateur pour saisir les données"""
    print("Choisissez une option:")
    print("1. Chiffrer un message")
    print("2. Déchiffrer un message")
    print("3. Démonstration avec un exemple")
    print("4. Quitter")
    print()

    choice = input("Votre choix (1-4): ").strip()
    return choice


def validate_key(key):
    """Valide que la clé ne contient que des lettres"""
    if not key:
        return False, "La clé ne peut pas être vide."
    
    if not key.isalpha():
        return False, "La clé doit contenir uniquement des lettres (a-z, A-Z)."
    
    return True, ""


def encrypt_message(vigenere):
    """Interface pour chiffrer un message"""
    print("\n--- CHIFFREMENT VIGENÈRE ---")

    # Saisie du message
    message = input("Entrez le message à chiffrer: ")
    if not message:
        print("Erreur: Le message ne peut pas être vide.")
        return

    # Saisie de la clé
    key = input("Entrez la clé (lettres uniquement): ").strip()
    is_valid, error_msg = validate_key(key)
    if not is_valid:
        print(f"Erreur: {error_msg}")
        return

    try:
        # Chiffrement
        encrypted_data = vigenere.chiffrer_vigenere(message, key)

        # Affichage des résultats
        print("\n--- RÉSULTATS DU CHIFFREMENT ---")
        print(f"Message original: {message}")
        print(f"Clé utilisée: {key}")
        print(f"Message chiffré: {encrypted_data}")
        print(f"Message chiffré (base64): {base64.b64encode(encrypted_data.encode('utf-8')).decode()}")

    except Exception as e:
        print(f"Erreur lors du chiffrement: {e}")


def decrypt_message(vigenere):
    """Interface pour déchiffrer un message"""
    print("\n--- DÉCHIFFREMENT VIGENÈRE ---")

    # Saisie du message chiffré
    print("Format du message chiffré:")
    print("1. Texte normal")
    print("2. Base64")

    format_choice = input("Votre choix (1-2): ").strip()

    encrypted_input = input("Entrez le message chiffré: ").strip()
    if not encrypted_input:
        print("Erreur: Le message chiffré ne peut pas être vide.")
        return

    try:
        if format_choice == "1":
            encrypted_data = encrypted_input
        elif format_choice == "2":
            encrypted_data = base64.b64decode(encrypted_input).decode('utf-8')
        else:
            print("Choix invalide.")
            return
    except Exception as e:
        print(f"Erreur lors de la conversion du message chiffré: {e}")
        return

    # Saisie de la clé
    key = input("Entrez la clé (lettres uniquement): ").strip()
    is_valid, error_msg = validate_key(key)
    if not is_valid:
        print(f"Erreur: {error_msg}")
        return

    try:
        # Déchiffrement
        decrypted_message = vigenere.dechiffrer_vigenere(encrypted_data, key)

        # Affichage des résultats
        print("\n--- RÉSULTATS DU DÉCHIFFREMENT ---")
        print(f"Message déchiffré: {decrypted_message}")

    except Exception as e:
        print(f"Erreur lors du déchiffrement: {e}")


def show_demonstration(vigenere):
    """Démonstration avec un exemple prédéfini"""
    print("\n--- DÉMONSTRATION ---")
    
    message = "Bonjour le monde! Comment allez-vous?"
    key = "SECRET"
    
    print(f"Message original: {message}")
    print(f"Clé utilisée: {key}")
    
    # Chiffrement
    encrypted = vigenere.chiffrer_vigenere(message, key)
    print(f"Message chiffré: {encrypted}")
    
    # Déchiffrement
    decrypted = vigenere.dechiffrer_vigenere(encrypted, key)
    print(f"Message déchiffré: {decrypted}")
    
    # Vérification
    if message == decrypted:
        print("\n✅ Démonstration réussie! Le message original a été correctement récupéré.")
    else:
        print("\n❌ Erreur dans la démonstration.")
    
    print("\n--- EXPLICATION DU CHIFFRE DE VIGENÈRE ---")
    print("Le chiffre de Vigenère utilise une clé répétée pour chiffrer chaque lettre.")
    print("Chaque lettre du message est décalée selon la lettre correspondante de la clé.")
    print("Par exemple, avec la clé 'SECRET':")
    print("- La 1ère lettre est décalée de S (18 positions)")
    print("- La 2ème lettre est décalée de E (4 positions)")
    print("- La 3ème lettre est décalée de C (2 positions)")
    print("- Et ainsi de suite, en répétant la clé...")


def main_vigenere():
    """Fonction principale"""
    vigenere = VigenereCipher()

    while True:
        print_banner()
        choice = get_user_input()

        if choice == "1":
            encrypt_message(vigenere)
        elif choice == "2":
            decrypt_message(vigenere)
        elif choice == "3":
            show_demonstration(vigenere)
        elif choice == "4":
            print("Au revoir!")
            break
        else:
            print("Choix invalide. Veuillez choisir entre 1 et 4.")

        input("\nAppuyez sur Entrée pour continuer...")
        print("\n" * 2)


if __name__ == "__main__":
    main_vigenere()