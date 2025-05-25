def rc4_key_scheduling(key):
    """
    RC4 Key Scheduling Algorithm (KSA)
    
    Args:
        key (bytes or str): The secret key for encryption
        
    Returns:
        list: The initialized S-box (state array)
    """
    # Convert string key to bytes if necessary
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    # Validate key length
    if not (1 <= len(key) <= 256):
        raise ValueError("Key length must be between 1 and 256 bytes")
    
    # Initialize S-box with values 0 to 255
    S = list(range(256))
    
    # Key scheduling
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        # Swap S[i] and S[j]
        S[i], S[j] = S[j], S[i]
    
    return S


def rc4_generate_keystream(S, length):
    """
    RC4 Pseudo-Random Generation Algorithm (PRGA)
    
    Args:
        S (list): The S-box from key scheduling
        length (int): Number of keystream bytes to generate
        
    Returns:
        bytes: The generated keystream
    """
    # Make a copy to avoid modifying original S-box
    S = S.copy()
    
    i = j = 0
    keystream = []
    
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        
        # Swap S[i] and S[j]
        S[i], S[j] = S[j], S[i]
        
        # Generate keystream byte
        K = S[(S[i] + S[j]) % 256]
        keystream.append(K)
    
    return bytes(keystream)


def rc4_encrypt(plaintext, key):
    """
    RC4 Encryption Function
    
    Args:
        plaintext (bytes or str): Data to encrypt
        key (bytes or str): Secret key
        
    Returns:
        bytes: Encrypted ciphertext
    """
    # Convert string to bytes if necessary
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # Perform key scheduling
    S = rc4_key_scheduling(key)
    
    # Generate keystream of same length as plaintext
    keystream = rc4_generate_keystream(S, len(plaintext))
    
    # XOR plaintext with keystream
    ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))
    
    return ciphertext


def rc4_decrypt(ciphertext, key):
    """
    RC4 Decryption Function
    (Same as encryption due to XOR properties)
    
    Args:
        ciphertext (bytes): Data to decrypt
        key (bytes or str): Secret key
        
    Returns:
        bytes: Decrypted plaintext
    """
    return rc4_encrypt(ciphertext, key)


def rc4_encrypt_string(plaintext, key):
    """
    Convenience function to encrypt string and return hex
    
    Args:
        plaintext (str): Text to encrypt
        key (str): Secret key
        
    Returns:
        str: Hex representation of ciphertext
    """
    ciphertext = rc4_encrypt(plaintext, key)
    return ciphertext.hex()


def rc4_decrypt_string(hex_ciphertext, key):
    """
    Convenience function to decrypt hex string
    
    Args:
        hex_ciphertext (str): Hex representation of ciphertext
        key (str): Secret key
        
    Returns:
        str: Decrypted plaintext
    """
    ciphertext = bytes.fromhex(hex_ciphertext)
    plaintext = rc4_decrypt(ciphertext, key)
    return plaintext.decode('utf-8')


def demonstrate_rc4():
    """
    Demonstration of RC4 algorithm usage
    """
    print("🔐 RC4 Algorithm Demonstration")
    print("=" * 40)
    
    # Test data
    message = "Hello, World! This is RC4 encryption."
    secret_key = "MySecretKey123"
    
    print(f"📝 Original message: {message}")
    print(f"🗝️  Secret key: {secret_key}")
    print()
    
    # Encrypt
    encrypted_hex = rc4_encrypt_string(message, secret_key)
    print(f"🔒 Encrypted (hex): {encrypted_hex}")
    
    # Decrypt
    decrypted_message = rc4_decrypt_string(encrypted_hex, secret_key)
    print(f"🔓 Decrypted message: {decrypted_message}")
    
    # Verify
    print(f"✅ Encryption/Decryption successful: {message == decrypted_message}")
    
    print("\n" + "=" * 40)
    print("🔍 Step-by-step process:")
    
    # Show S-box initialization
    S = rc4_key_scheduling(secret_key)
    print(f"📦 S-box first 10 values: {S[:10]}")
    
    # Show keystream generation
    keystream = rc4_generate_keystream(S, 10)
    print(f"🎲 Keystream first 10 bytes: {list(keystream)}")


# Additional utility functions
def rc4_analyze_keystream(key, length=100):
    """
    Analyze RC4 keystream properties
    
    Args:
        key (str): Secret key
        length (int): Length of keystream to analyze
        
    Returns:
        dict: Analysis results
    """
    S = rc4_key_scheduling(key)
    keystream = rc4_generate_keystream(S, length)
    
    # Basic statistics
    byte_counts = [0] * 256
    for byte in keystream:
        byte_counts[byte] += 1
    
    return {
        'length': length,
        'unique_bytes': len([c for c in byte_counts if c > 0]),
        'most_frequent': max(range(256), key=lambda x: byte_counts[x]),
        'frequency': max(byte_counts),
        'average': sum(keystream) / len(keystream)
    }


if __name__ == "__main__":
    # Run demonstration
    demonstrate_rc4()
    
    print("\n🔬 Keystream Analysis:")
    analysis = rc4_analyze_keystream("TestKey", 1000)
    for key, value in analysis.items():
        print(f"   {key}: {value}")