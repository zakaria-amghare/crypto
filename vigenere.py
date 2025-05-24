def dechiffrer_vigenere(ciphertext, key):
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

if __name__ == "__main__":
    ciphertext = input("Entrez le texte chiffré : ")
    key = input("Entrez la clé : ")
    resultat = dechiffrer_vigenere(ciphertext, key)
    print("Texte déchiffré :", resultat)
