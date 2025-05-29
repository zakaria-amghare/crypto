import string
from math import gcd


def affine_encrypt(text, a, b):
    if gcd(26, a) != 1:
        raise ValueError("'a' Doit etre premier avec 26, veuillez choisir un autre parametre 'a' ")
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
        raise ValueError("'a' Doit etre premier avec 26, veuillez choisir un autre parametre 'a' ")
    else:
        crypted_text = crypted_text.upper()
        alphabet = string.ascii_uppercase
        decrypted_text = ""
        inv_a = find_inverse(a)
        for char in crypted_text:
            if char in alphabet:
                y=alphabet.index(char)
                decrypted_text+=alphabet[inv_a*(y-b) % 26]
            else:
                decrypted_text+=char
        return decrypted_text

#Test
a,b=5,9
text = 'Ramadan mubarak !'
crypted=affine_encrypt(text,a,b)
print("Texte chiffre : ",crypted)

decrypted=affine_decrypt(crypted,a,b)
print("Texte dechiffre: ",decrypted)