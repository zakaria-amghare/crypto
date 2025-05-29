import numpy as np
import string
from sympy import Matrix


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


# Test
key_matrix = np.array([[3, 3], [2, 5]])
message = "Ramadhan"
cipher = hill_encrypt(message, key_matrix)
print("Texte chiffré :", cipher)

decrypted = hill_decrypt(cipher, key_matrix)
print("Texte déchiffré :", decrypted)
