
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


# Test
playfair_key = "KEYWORD"
message = "crypto"
cipher = playfair_encrypt(message, playfair_key)
print("Texte chiffré (Playfair) :", cipher)

decrypted = playfair_decrypt(cipher, playfair_key)
print("Texte déchiffré (Playfair) :", decrypted)
