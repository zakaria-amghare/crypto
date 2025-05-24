from random_prime import *
import math

def gcd(a, b):
    """Calcul du PGCD avec l'algorithme d'Euclide"""
    while b:
        a, b = b, a % b
    return a

def RSA_keys():
    """
    Implémentation corrigée de l'algorithme RSA.
    """
    p = generate_512_bit_prime()    
    q = generate_512_bit_prime()
    
    while p == q:
        print("p et q identiques, régénération de q...")
        q = generate_512_bit_prime()
    
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = 65537  # Valeur courante pour e, souvent utilisée dans RSA
    # Step 5: Compute d, the modular multiplicative inverse of e mod φ(n)
    try:
        d = pow(e, -1, phi_n)
    except ValueError:
        raise ValueError("Impossible de calculer l'inverse modulaire de e")

    # Step 6: Public key is (e, n) and private key is (d, n)
    public_key = (e, n)
    private_key = (d, n)
    

    return public_key, private_key, p, q

def RSA_encrypt(message, public_key):
    """
    Chiffre un message en utilisant la clé publique RSA.
    """
    e, n = public_key
    
    # Convert message to integer
    message_bytes = message.encode('utf-8')
    message_int = int.from_bytes(message_bytes, 'big')
    
    # Vérifier que le message est plus petit que n
    if message_int >= n:
        max_bytes = (n.bit_length() - 1) // 8
        raise ValueError(f"Message trop long. Taille maximale: {max_bytes} bytes, "
                        f"taille actuelle: {len(message_bytes)} bytes")
    
    # Encrypt the message
    encrypted_message = pow(message_int, e, n)
    return encrypted_message

def RSA_decrypt(encrypted_message, private_key):
    """
    Déchiffre un message en utilisant la clé privée RSA.
    """
    d, n = private_key
    
    # Decrypt the message
    decrypted_message_int = pow(encrypted_message, d, n)
    
    # Convert integer back to string
    try:
        # Calculer le nombre de bytes nécessaires
        byte_length = (decrypted_message_int.bit_length() + 7) // 8
        if byte_length == 0:  # Cas où le message déchiffré est 0
            byte_length = 1
        
        decrypted_bytes = decrypted_message_int.to_bytes(byte_length, 'big')
        decrypted_message = decrypted_bytes.decode('utf-8')
        return decrypted_message
    except (UnicodeDecodeError, OverflowError) as e:
        raise ValueError(f"Erreur lors du déchiffrement: {e}")

def test_message_size_limit(public_key):
    """
    Teste la limite de taille des messages
    """
    e, n = public_key
    max_bytes = (n.bit_length() - 1) // 8
    
    print(f"\nTest des limites de taille:")
    print(f"Taille maximale théorique: {max_bytes} bytes")
    
    # Test avec un message à la limite
    test_message = "A" * (max_bytes - 10)  # Message proche de la limite
    try:
        encrypted = RSA_encrypt(test_message, public_key)
        print(f"Message de {len(test_message)} bytes: OK")
    except ValueError as e:
        print(f"Message de {len(test_message)} bytes: ERREUR - {e}")
    
    # Test avec un message trop long
    try:
        long_message = "A" * (max_bytes + 10)
        encrypted = RSA_encrypt(long_message, public_key)
        print(f"Message de {len(long_message)} bytes: OK (ne devrait pas arriver)")
    except ValueError as e:
        print(f"Message de {len(long_message)} bytes: ERREUR attendue - {e}")

# Test principal
def main():
    print("=== Test de l'implémentation RSA corrigée ===")
    
    # Test avec un message court
    message = "Hellokitty"
    print(f"\nMessage original: '{message}'")
    
    try:
        public_key, private_key, p, q = RSA_keys()
        
        # Chiffrement
        encrypted_message = RSA_encrypt(message, public_key)
        
        print(f"Message chiffré: {encrypted_message}")
        # Déchiffrement
        decrypted_message = RSA_decrypt(encrypted_message, private_key)
        
        # Test des limites de taille
        test_message_size_limit(public_key)
        
        # Informations supplémentaires
        print(f"\n=== Informations de la clé ===")
        print(f"p: {p}")
        print(f"q: {q}")
        print(f"n: {public_key[1]}")
        print(f"e: {public_key[0]}")
        print(f"d: {private_key[0]}")
        
        # Vérification
        if message == decrypted_message:
            print(f"Message déchiffré: '{decrypted_message}'")
            print("✓ Test réussi: Le message déchiffré correspond au message original")
        else:
            print("✗ Test échoué: Le message déchiffré ne correspond pas")
        
    except Exception as e:
        print(f"Erreur: {e}")

if __name__ == "__main__":
    main()