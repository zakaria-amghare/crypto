# Enhanced Cryptography Implementation with Symmetric/Asymmetric Organization
from AES import *
from DES import *
from RSA import *
from RC4 import *
from Diffie_Hellman import *
from ElGamal import *
from vigenere import *
from kasiskiAndSomeFunction import *
from dechiffrement_cesar import *
import os
def clear():
    """Clear the console screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def display_main_menu():
    """Display the main menu with symmetric/asymmetric categories"""
    print("\n" + "="*60)
    print("🔐 PROGRAMME DE CHIFFREMENT ET DÉCHIFFREMENT 🔐")
    print("="*60)
    print("Choisissez une catégorie:")
    print("1. 🔑 Chiffrement Symétrique")
    print("2. 🗝️  Chiffrement Asymétrique") 
    print("3. 🔍 Analyse Cryptographique")
    print("0. ❌ Quitter")
    print("="*60)

def display_symmetric_menu():
    """Display symmetric cryptography options"""
    print("\n" + "-"*50)
    print("🔑 CHIFFREMENT SYMÉTRIQUE")
    print("-"*50)
    print("📚 Algorithmes Classiques (Historiques):")
    print("  1. César (Substitution)")
    print("  2. Vigenère (Polyalphabétique)")
    print("")
    print("💻 Algorithmes Modernes:")
    print("  3. RC4 (Stream Cipher)")
    print("  4. DES (Data Encryption Standard)")
    print("  5. AES (Advanced Encryption Standard)")
    print("")
    print("  0. ⬅️  Retour au menu principal")
    print("-"*50)

def display_asymmetric_menu():
    """Display asymmetric cryptography options"""
    print("\n" + "-"*50)
    print("🗝️  CHIFFREMENT ASYMÉTRIQUE")
    print("-"*50)
    print("  1. RSA (Rivest-Shamir-Adleman)")
    print("  2. ElGamal (Taher ElGamal)")
    print("  3. Diffie-Hellman (Échange de clés)")
    print("")
    print("  0. ⬅️  Retour au menu principal")
    print("-"*50)

def display_analysis_menu():
    """Display cryptanalysis options"""
    print("\n" + "-"*50)
    print("🔍 ANALYSE CRYPTOGRAPHIQUE")
    print("-"*50)
    print("  1. Test de Kasiski et fonctions d'analyse")
    print("  2. Déchiffrement César (Force brute)")
    print("")
    print("  0. ⬅️  Retour au menu principal")
    print("-"*50)

def handle_symmetric_choice():
    """Handle symmetric cryptography menu"""
    while True:
        display_symmetric_menu()
        choice = input("Entrez votre choix (0-5): ").strip()
        
        if choice == '1':
            print("🏛️  Lancement du déchiffrement César...")
            main_cesar()
        elif choice == '2':
            print("📜 Lancement de Vigenère...")
            main_vigenere()
        elif choice == '3':
            print("🌊 Lancement de RC4...")
            main_RC4()
        elif choice == '4':
            print("🏢 Lancement de DES...")
            main_DES()
        elif choice == '5':
            print("⭐ Lancement d'AES...")
            main_AES()
        elif choice == '0':
            break
        else:
            print("❌ Choix invalide, veuillez réessayer.")

def handle_asymmetric_choice():
    """Handle asymmetric cryptography menu"""
    while True:
        display_asymmetric_menu()
        choice = input("Entrez votre choix (0-3): ").strip()
        
        if choice == '1':
            print("🔐 Lancement de RSA...")
            main_RSA()
        elif choice == '2':
            print("🔑 Lancement d'ElGamal...")
            main_ELGamal()
        elif choice == '3':
            print("🤝 Lancement de Diffie-Hellman...")
            main_DiffieHellman()
        elif choice == '0':
            break
        else:
            print("❌ Choix invalide, veuillez réessayer.")

def handle_analysis_choice():
    """Handle cryptanalysis menu"""
    while True:
        display_analysis_menu()
        choice = input("Entrez votre choix (0-2): ").strip()
        
        if choice == '1':
            print("🔬 Lancement de l'analyse Kasiski...")
            kasiski_main()
        elif choice == '2':
            print("🔓 Lancement du déchiffrement César...")
            main_cesar()
        elif choice == '0':
            break
        else:
            print("❌ Choix invalide, veuillez réessayer.")

def main():
    """Main program function"""
    while True:
        display_main_menu()
        choice = input("Entrez votre choix (0-3): ").strip()
        
        if choice == '1':
            handle_symmetric_choice()
        elif choice == '2':
            handle_asymmetric_choice()
        elif choice == '3':
            handle_analysis_choice()
        elif choice == '0':
            print("\n🎉 Merci d'avoir utilisé le programme de cryptographie!")
            print("👋 Au revoir et à bientôt!")
            break
        else:
            print("❌ Choix invalide, veuillez réessayer.")
        clear()
if __name__ == "__main__":
    main()