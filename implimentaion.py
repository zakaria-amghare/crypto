# implimentaion 
from AES import *
from DES import *
from RSA import *
from RC4 import *
from Diffie_Hellman import *
from ElGamal import *
from vigenere import *
from kasiskiAndSomeFunction import *
from dechiffrement_cesar import *

def main():
    print("Bienvenue dans le programme de chiffrement et déchiffrement!")
    print("Choisissez une option:")
    print("1. RC4")
    print("2. AES")
    print("3. DES")
    print("4. RSA")
    print("5. Diffie-Hellman")
    print("6. ElGamal")
    print("7. Vigenère")
    print("8. Kasiski et autres fonctions")
    print("9. Déchiffrement César")
    print("0. Quitter")
    
    while True:
        choice = input("Entrez votre choix (0-9): ")
        
        if choice == '1':
            main_RC4()
        elif choice == '2':
            main_AES()
        elif choice == '3':
            main_DES()
        elif choice == '4':
            main_RSA()
        elif choice == '5':
            main_DiffieHellman()
        elif choice == '6':
            main_ELGamal()
        elif choice == '7':
            main_vigenere()
        elif choice == '8':
            kasiski_main()
        elif choice == '9':
            main_cesar()
        elif choice == '0':
            print("Merci d'avoir utilisé le programme. Au revoir!")
            break
        else:
            print("Choix invalide, veuillez réessayer.")
if __name__ == "__main__":
    main()