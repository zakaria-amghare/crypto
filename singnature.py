import hashlib
import random
import math

def is_prime(n, k=5):
    """Miller-Rabin primality test"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n-1 as 2^r * d
    r = 0
    d = n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    """Generate a random prime number of specified bit length"""
    while True:
        num = random.getrandbits(bits)
        num |= (1 << bits - 1) | 1  # Ensure it's odd and has correct bit length
        if is_prime(num):
            return num

def extended_gcd(a, b):
    """Extended Euclidean Algorithm"""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(e, phi):
    """Calculate modular multiplicative inverse"""
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return (x % phi + phi) % phi

def generate_rsa_keypair(key_size=1024):
    """
    Generate RSA public and private key pair
    Returns: (public_key, private_key) where keys are tuples (exponent, modulus)
    """
    # Generate two distinct prime numbers
    p = generate_prime(key_size // 2)
    q = generate_prime(key_size // 2)
    while p == q:
        q = generate_prime(key_size // 2)
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Choose e (commonly 65537)
    e = 65537
    while math.gcd(e, phi) != 1:
        e += 2
    
    # Calculate d (private exponent)
    d = mod_inverse(e, phi)
    
    # Public key: (e, n), Private key: (d, n)
    public_key = (e, n)
    private_key = (d, n)
    
    return public_key, private_key

def hash_message(message):
    """Create SHA-256 hash of the message"""
    if isinstance(message, str):
        message = message.encode('utf-8')
    return hashlib.sha256(message).digest()

def bytes_to_int(bytes_data):
    """Convert bytes to integer"""
    return int.from_bytes(bytes_data, byteorder='big')

def int_to_bytes(num, length):
    """Convert integer to bytes"""
    return num.to_bytes(length, byteorder='big')

def sign_message(message, private_key):
    """
    Create a digital signature for the message
    Args:
        message: String or bytes to sign
        private_key: Tuple (d, n) - private key components
    Returns: signature as bytes
    """
    # Hash the message
    message_hash = hash_message(message)
    hash_int = bytes_to_int(message_hash)
    
    # Sign with private key (d, n)
    d, n = private_key
    signature_int = pow(hash_int, d, n)
    
    # Convert back to bytes
    byte_length = (n.bit_length() + 7) // 8
    signature = int_to_bytes(signature_int, byte_length)
    
    return signature

def verify_signature(message, signature, public_key):
    """
    Verify a digital signature
    Args:
        message: Original message (string or bytes)
        signature: Signature bytes to verify
        public_key: Tuple (e, n) - public key components
    Returns: True if signature is valid, False otherwise
    """
    try:
        # Hash the message
        message_hash = hash_message(message)
        hash_int = bytes_to_int(message_hash)
        
        # Convert signature to integer
        signature_int = bytes_to_int(signature)
        
        # Verify with public key (e, n)
        e, n = public_key
        decrypted_hash_int = pow(signature_int, e, n)
        
        # Compare hashes
        return hash_int == decrypted_hash_int
        
    except Exception:
        return False

def export_key_info(public_key, private_key):
    """
    Export keys in a readable format
    Args:
        public_key: Tuple (e, n)
        private_key: Tuple (d, n)
    Returns: Dictionary with key information
    """
    e, n = public_key
    d, _ = private_key
    
    return {
        'public_key': {
            'e': e,
            'n': n
        },
        'private_key': {
            'd': d,
            'n': n
        },
        'key_size_bits': n.bit_length()
    }

def create_signature_system(key_size=1024):
    """
    Convenience function to create a complete signature system
    Returns: Dictionary with keys and helper functions
    """
    public_key, private_key = generate_rsa_keypair(key_size)
    
    def sign(message):
        return sign_message(message, private_key)
    
    def verify(message, signature):
        return verify_signature(message, signature, public_key)
    
    def get_public_key():
        return public_key
    
    def get_key_info():
        return export_key_info(public_key, private_key)
    
    return {
        'sign': sign,
        'verify': verify,
        'get_public_key': get_public_key,
        'get_key_info': get_key_info,
        'public_key': public_key,
        'private_key': private_key
    }

# Example usage and demonstration
def main_RSA():
    print("🔐 Digital Signature Algorithm Demo (Function-based)")
    print("=" * 50)
    
    # Generate keys
    print("📋 Generating RSA key pair...")
    public_key, private_key = generate_rsa_keypair(key_size=512)  # Smaller for demo
    
    # Test message
    message = "Hello, this is a secure message!"
    print(f"📝 Original message: '{message}'")
    
    # Sign the message
    print("\n✍️  Signing message...")
    signature = sign_message(message, private_key)
    print(f"📋 Signature length: {len(signature)} bytes")
    print(f"📋 Signature (hex): {signature.hex()[:32]}...")
    
    # Verify the signature
    print("\n🔍 Verifying signature...")
    is_valid = verify_signature(message, signature, public_key)
    print(f"✅ Signature valid: {is_valid}")
    
    # Test with tampered message
    print("\n🚨 Testing with tampered message...")
    tampered_message = "Hello, this is a TAMPERED message!"
    is_valid_tampered = verify_signature(tampered_message, signature, public_key)
    print(f"❌ Tampered signature valid: {is_valid_tampered}")
    
    # Test convenience function
    print("\n🎯 Testing convenience signature system...")
    sig_system = create_signature_system(key_size=512)
    
    test_msg = "Testing convenience functions!"
    test_signature = sig_system['sign'](test_msg)
    test_valid = sig_system['verify'](test_msg, test_signature)
    print(f"📝 Test message: '{test_msg}'")
    print(f"✅ Convenience system valid: {test_valid}")
    
    # Export key information
    print("\n🔑 Key Information:")
    key_info = export_key_info(public_key, private_key)
    print(f"Public key (e): {key_info['public_key']['e']}")
    print(f"Public key (n): {str(key_info['public_key']['n'])[:20]}...")
    print(f"Private key (d): {str(key_info['private_key']['d'])[:20]}...")
    print(f"Key size: {key_info['key_size_bits']} bits")
    
    print("\n🎉 Function-based digital signature demonstration complete!")

# Additional utility functions

def sign_multiple_messages(messages, private_key):
    """Sign multiple messages at once"""
    signatures = []
    for msg in messages:
        sig = sign_message(msg, private_key)
        signatures.append(sig)
    return signatures

def verify_multiple_signatures(messages, signatures, public_key):
    """Verify multiple message-signature pairs"""
    results = []
    for msg, sig in zip(messages, signatures):
        valid = verify_signature(msg, sig, public_key)
        results.append(valid)
    return results

def create_message_signature_pair(message, private_key):
    """Create a message-signature pair for easy transmission"""
    signature = sign_message(message, private_key)
    return {
        'message': message,
        'signature': signature.hex(),  # Hex for easy transmission
        'signature_bytes': signature
    }

def verify_message_signature_pair(pair, public_key):

    """Verify a message-signature pair"""
    message = pair['message']
    signature_bytes = pair['signature_bytes']
    return verify_signature(message, signature_bytes, public_key)

main_RSA()  # Run the demonstration