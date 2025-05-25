#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced César Cipher Tool with Frequency Analysis

Ce programme permet de chiffrer, déchiffrer et analyser des textes avec le chiffre de César.
Il inclut l'analyse fréquentielle pour casser automatiquement le chiffrement.

@author: Enhanced version based on original by Michee Nonga Mahukola
"""

import string
import random
import base64

class CesarCipher:
    def __init__(self):
        # ABC...Z
        self.LETTERS = string.ascii_uppercase
        # Fréquence d'apparition des lettres en Français
        # Source: Wikipedia - Analyse fréquentielle
        self.FR_FREQ = {
            'a': 9.2, 'b': 1.02, 'c': 2.64, 'd': 3.39, 'e': 15.87, 'f': 0.95,
            'g': 1.04, 'h': 0.77, 'i': 8.41, 'j': 0.89, 'k': 0.00, 'l': 5.34,
            'm': 3.24, 'n': 7.15, 'o': 5.14, 'p': 2.86, 'q': 1.06, 'r': 6.46,
            's': 7.90, 't': 7.26, 'u': 6.24, 'v': 2.15, 'w': 0.00, 'x': 0.30,
            'y': 0.24, 'z': 0.32
        }

    def chiffrement_additif(self, text, cle):
        """Chiffre un texte avec le chiffre de César"""
        text = text.upper()
        result = ""
        for i in text:
            if i in [" ", "\t", "\n"]:
                result = result + i
            else:
                pos = self.LETTERS.find(i)
                if pos >= 0:
                    result = result + self.LETTERS[(pos + cle) % 26]
                else:
                    result = result + i
        return result

    def dechiffrement_additif(self, text, cle):
        """Déchiffre un texte avec le chiffre de César"""
        text = text.upper()
        result = ""
        for i in text:
            if i in [" ", "\t", "\n"]:
                result = result + i
            else:
                pos = self.LETTERS.find(i)
                if pos >= 0:
                    result = result + self.LETTERS[(pos - cle) % 26]
                else:
                    result = result + i
        return result

    def analyse_frequentielle(self, text, nb_resultats=5):
        """
        Analyse fréquentielle pour casser automatiquement le chiffre de César
        Retourne les meilleurs candidats basés sur la fréquence des lettres
        """
        text = text.upper()
        dechiffre_list = []
        frequences_list = []
        ponderation_list = {}
        
        for i in range(26):
            dechiffre = self.dechiffrement_additif(text, i)
            dechiffre_list.append(dechiffre)
            frequences = {}
            ponderation = 0
            
            # Compter seulement les lettres pour le calcul de fréquence
            lettres_seulement = ''.join([c for c in dechiffre if c.isalpha()])
            longueur_lettres = len(lettres_seulement)
            
            if longueur_lettres > 0:
                for j in self.LETTERS:
                    # Fréquence du caractère dans la phrase
                    freq = dechiffre.count(j) * 100 / longueur_lettres
                    frequences[j] = freq
                    # On pondère la fréquence avec les statistiques françaises
                    ponderation += freq * self.FR_FREQ[j.lower()]
            
            frequences_list.append(frequences)
            # On stocke la pondération pour cette phrase
            ponderation_list[i] = ponderation
            
        # Trier par ordre décroissant de pondération
        result = sorted(ponderation_list.items(), key=lambda x: x[1], reverse=True)
        
        # Retourner les meilleurs résultats
        resultats = []
        for i, (cle, ponderation) in enumerate(result[:nb_resultats]):
            resultats.append({
                'cle': cle,
                'ponderation': ponderation,
                'texte': dechiffre_list[cle],
                'rang': i + 1
            })
        
        return resultats

    def print_table_chiffrement(self, cle):
        """Affiche la table de chiffrement pour une clé donnée"""
        print(f"TABLE DE CHIFFREMENT, CLÉ : {cle}")
        
        for i, char in enumerate(self.LETTERS):
            print("%4d" % i, end="")
        print("")
        print('-' * (26 * 4))
        for i, char in enumerate(self.LETTERS):
            print("%4s" % char, end="")
        print("")
        print('-' * (26 * 4))
        for i, char in enumerate(self.LETTERS):
            print("%4s" % self.LETTERS[(i + cle) % 26], end="")
        print("")
        print('-' * (26 * 4))

    def print_table_dechiffrement(self, cle):
        """Affiche la table de déchiffrement pour une clé donnée"""
        print(f"TABLE DE DÉCHIFFREMENT, CLÉ : {cle}")
        
        for i, char in enumerate(self.LETTERS):
            print("%4d" % i, end="")
        print("")
        print('-' * (26 * 4))
        for i, char in enumerate(self.LETTERS):
            print("%4s" % char, end="")
        print("")
        print('-' * (26 * 4))
        for i, char in enumerate(self.LETTERS):
            print("%4s" % self.LETTERS[(i - cle) % 26], end="")
        print("")
        print('-' * (26 * 4))


def print_banner():
    print("=" * 60)
    print("        CHIFFRE DE CÉSAR - OUTIL COMPLET")
    print("        (avec analyse fréquentielle)")
    print("=" * 60)
    print()


def get_user_input():
    """Interface utilisateur pour saisir les données"""
    print("Choisissez une option:")
    print("1. Chiffrer un message")
    print("2. Déchiffrer un message (avec clé connue)")
    print("3. Casser un chiffrement (analyse fréquentielle)")
    print("4. Afficher les tables de chiffrement/déchiffrement")
    print("5. Démonstration avec exemple")
    print("6. Quitter")
    print()

    choice = input("Votre choix (1-6): ").strip()
    return choice


def encrypt_message(cesar):
    """Interface pour chiffrer un message"""
    print("\n--- CHIFFREMENT CÉSAR ---")

    # Saisie du message
    message = input("Entrez le message à chiffrer: ")
    if not message:
        print("Erreur: Le message ne peut pas être vide.")
        return

    # Saisie de la clé
    print("\nOptions pour la clé:")
    print("1. Entrer une clé spécifique (0-25)")
    print("2. Générer une clé aléatoire")

    key_choice = input("Votre choix (1-2): ").strip()

    if key_choice == "1":
        try:
            key = int(input("Entrez la clé (nombre entre 0 et 25): "))
            if not (0 <= key <= 25):
                print("Erreur: La clé doit être entre 0 et 25.")
                return
        except ValueError:
            print("Erreur: Veuillez entrer un nombre valide.")
            return
    elif key_choice == "2":
        key = random.randint(1, 25)
        print(f"Clé générée aléatoirement: {key}")
    else:
        print("Choix invalide.")
        return

    try:
        # Chiffrement
        encrypted_data = cesar.chiffrement_additif(message, key)

        # Affichage des résultats
        print("\n--- RÉSULTATS DU CHIFFREMENT ---")
        print(f"Message original: {message}")
        print(f"Clé utilisée: {key}")
        print(f"Message chiffré: {encrypted_data}")
        print(f"Message chiffré (base64): {base64.b64encode(encrypted_data.encode('utf-8')).decode()}")

    except Exception as e:
        print(f"Erreur lors du chiffrement: {e}")


def decrypt_message(cesar):
    """Interface pour déchiffrer un message avec clé connue"""
    print("\n--- DÉCHIFFREMENT CÉSAR (CLÉ CONNUE) ---")

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
    try:
        key = int(input("Entrez la clé (nombre entre 0 et 25): "))
        if not (0 <= key <= 25):
            print("Erreur: La clé doit être entre 0 et 25.")
            return
    except ValueError:
        print("Erreur: Veuillez entrer un nombre valide.")
        return

    try:
        # Déchiffrement
        decrypted_message = cesar.dechiffrement_additif(encrypted_data, key)

        # Affichage des résultats
        print("\n--- RÉSULTATS DU DÉCHIFFREMENT ---")
        print(f"Message déchiffré: {decrypted_message}")

    except Exception as e:
        print(f"Erreur lors du déchiffrement: {e}")


def crack_cipher(cesar):
    """Interface pour casser un chiffrement par analyse fréquentielle"""
    print("\n--- CASSAGE PAR ANALYSE FRÉQUENTIELLE ---")

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

    # Nombre de résultats à afficher
    try:
        nb_resultats = int(input("Combien de candidats voulez-vous voir? (1-10): "))
        if not (1 <= nb_resultats <= 10):
            nb_resultats = 5
            print("Nombre invalide, utilisation de 5 par défaut.")
    except ValueError:
        nb_resultats = 5
        print("Nombre invalide, utilisation de 5 par défaut.")

    try:
        # Analyse fréquentielle
        resultats = cesar.analyse_frequentielle(encrypted_data, nb_resultats)

        # Affichage des résultats
        print(f"\n--- LES {nb_resultats} MEILLEURS CANDIDATS ---")
        print("-" * 80)
        
        for resultat in resultats:
            print(f"#{resultat['rang']} - Clé {resultat['cle']:2d}, Pondération: {resultat['ponderation']:6.2f}")
            print(f"Texte: {resultat['texte']}")
            print("-" * 80)

        print("\n💡 Conseil: Le texte avec la pondération la plus élevée est probablement le bon!")
        print("La pondération est basée sur la fréquence des lettres en français.")

    except Exception as e:
        print(f"Erreur lors de l'analyse: {e}")


def show_tables(cesar):
    """Interface pour afficher les tables de chiffrement/déchiffrement"""
    print("\n--- TABLES DE CHIFFREMENT/DÉCHIFFREMENT ---")

    try:
        key = int(input("Entrez la clé pour laquelle afficher les tables (0-25): "))
        if not (0 <= key <= 25):
            print("Erreur: La clé doit être entre 0 et 25.")
            return
    except ValueError:
        print("Erreur: Veuillez entrer un nombre valide.")
        return

    print("\n")
    cesar.print_table_chiffrement(key)
    print("\n")
    cesar.print_table_dechiffrement(key)


def show_demonstration(cesar):
    """Démonstration complète avec exemple"""
    print("\n--- DÉMONSTRATION COMPLÈTE ---")
    
    message = "Bonjour tout le monde! Ceci est un test du chiffre de César."
    key = 7
    
    print(f"Message original: {message}")
    print(f"Clé utilisée: {key}")
    
    # Chiffrement
    encrypted = cesar.chiffrement_additif(message, key)
    print(f"Message chiffré: {encrypted}")
    
    # Déchiffrement avec clé connue
    decrypted = cesar.dechiffrement_additif(encrypted, key)
    print(f"Message déchiffré (avec clé): {decrypted}")
    
    # Analyse fréquentielle (simulation d'un cassage)
    print("\n--- SIMULATION DE CASSAGE ---")
    resultats = cesar.analyse_frequentielle(encrypted, 3)
    
    print("Les 3 meilleurs candidats selon l'analyse fréquentielle:")
    for resultat in resultats:
        print(f"Clé {resultat['cle']:2d} (pondération {resultat['ponderation']:6.2f}): {resultat['texte'][:50]}...")
    
    # Vérification
    if message.upper() == decrypted:
        print("\n✅ Démonstration réussie!")
        if resultats[0]['cle'] == key:
            print("🎯 L'analyse fréquentielle a trouvé la bonne clé en première position!")
        else:
            print(f"⚠️  L'analyse fréquentielle a proposé la clé {resultats[0]['cle']} au lieu de {key}")
    else:
        print("\n❌ Erreur dans la démonstration.")


def main_cesar():
    """Fonction principale"""
    cesar = CesarCipher()

    while True:
        print_banner()
        choice = get_user_input()

        if choice == "1":
            encrypt_message(cesar)
        elif choice == "2":
            decrypt_message(cesar)
        elif choice == "3":
            crack_cipher(cesar)
        elif choice == "4":
            show_tables(cesar)
        elif choice == "5":
            show_demonstration(cesar)
        elif choice == "6":
            print("Au revoir!")
            break
        else:
            print("Choix invalide. Veuillez choisir entre 1 et 6.")

        input("\nAppuyez sur Entrée pour continuer...")
        print("\n" * 2)

