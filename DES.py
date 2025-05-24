# DES Algorithm - Function-based Implementation

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

def hex_to_bin(hex_str):
    """Convert hexadecimal string to binary string"""
    return bin(int(hex_str, 16))[2:].zfill(len(hex_str) * 4)

def bin_to_hex(bin_str):
    """Convert binary string to hexadecimal string"""
    return hex(int(bin_str, 2))[2:].upper().zfill(len(bin_str) // 4)

def permute(data, table):
    """Apply permutation using given table"""
    return ''.join(data[i - 1] for i in table)

def left_shift(data, shifts):
    """Perform left circular shift"""
    return data[shifts:] + data[:shifts]

def xor(a, b):
    """XOR two binary strings"""
    return ''.join('0' if a[i] == b[i] else '1' for i in range(len(a)))

def sbox_substitution(data):
    """Apply S-box substitution"""
    result = ''
    for i in range(8):
        block = data[i * 6:(i + 1) * 6]
        row = int(block[0] + block[5], 2)
        col = int(block[1:5], 2)
        val = S[i][row][col]
        result += format(val, '04b')
    return result

def generate_keys(key):
    """Generate 16 round keys from main key"""
    # Convert key to binary
    key_bin = hex_to_bin(key)
    
    # Apply PC1 permutation
    key_56 = permute(key_bin, PC1)
    
    # Split into left and right halves
    left = key_56[:28]
    right = key_56[28:]
    
    round_keys = []
    
    for i in range(16):
        # Perform left shifts
        left = left_shift(left, SHIFTS[i])
        right = left_shift(right, SHIFTS[i])
        
        # Combine and apply PC2
        combined = left + right
        round_key = permute(combined, PC2)
        round_keys.append(round_key)
    
    return round_keys

def f_function(right, key):
    """Feistel function"""
    # Expansion
    expanded = permute(right, E)
    
    # XOR with round key
    xor_result = xor(expanded, key)
    
    # S-box substitution
    substituted = sbox_substitution(xor_result)
    
    # Permutation
    result = permute(substituted, P)
    
    return result

def des_round(left, right, key):
    """Single DES round"""
    new_right = xor(left, f_function(right, key))
    return right, new_right

def des_encrypt(plaintext, key):
    """Encrypt plaintext using DES"""
    # Convert to binary
    plain_bin = hex_to_bin(plaintext)
    
    # Initial permutation
    permuted = permute(plain_bin, IP)
    
    # Split into left and right halves
    left = permuted[:32]
    right = permuted[32:]
    
    # Generate round keys
    round_keys = generate_keys(key)
    
    # 16 rounds of Feistel
    for i in range(16):
        left, right = des_round(left, right, round_keys[i])
    
    # Swap and combine
    combined = right + left
    
    # Final permutation
    ciphertext_bin = permute(combined, FP)
    
    # Convert to hex
    return bin_to_hex(ciphertext_bin)

def des_decrypt(ciphertext, key):
    """Decrypt ciphertext using DES"""
    # Convert to binary
    cipher_bin = hex_to_bin(ciphertext)
    
    # Initial permutation
    permuted = permute(cipher_bin, IP)
    
    # Split into left and right halves
    left = permuted[:32]
    right = permuted[32:]
    
    # Generate round keys (reverse order for decryption)
    round_keys = generate_keys(key)
    round_keys.reverse()
    
    # 16 rounds of Feistel
    for i in range(16):
        left, right = des_round(left, right, round_keys[i])
    
    # Swap and combine
    combined = right + left
    
    # Final permutation
    plaintext_bin = permute(combined, FP)
    
    # Convert to hex
    return bin_to_hex(plaintext_bin)


# Example usage
if __name__ == "__main__":
    # Example key and plaintext (64-bit each, in hexadecimal)
    key = "133457799BBCDFF1"
    plaintext = "0123456789ABCDEF"
    
    print(f"Key: {key}")
    print(f"Plaintext: {plaintext}")
    
    # Encrypt
    ciphertext = des_encrypt(plaintext, key)
    print(f"Ciphertext: {ciphertext}")
    
    # Decrypt
    decrypted = des_decrypt(ciphertext, key)
    print(f"Decrypted: {decrypted}")
    
    # Verify
    print(f"Decryption successful: {plaintext == decrypted}")
    
    # Show round keys
    print("\nRound Keys:")
    round_keys = generate_keys(key)
    for i, rk in enumerate(round_keys, 1):
        print(f"Round {i:2d}: {bin_to_hex(rk)}")