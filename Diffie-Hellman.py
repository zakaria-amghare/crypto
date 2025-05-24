import random
import hashlib
from math import gcd

# ============================================================================
# PART 1: PRIME GENERATION AND TESTING
# ============================================================================

def generate_random_prime(bits):
    """
    Generate a large prime number of specified bit length
    This is used to create the modulus 'p' in Diffie-Hellman
    
    Args:
        bits: Number of bits for the prime (e.g., 1024, 2048)
    
    Returns:
        A prime number with the specified bit length
    """
    print(f"Generating {bits}-bit prime number...")
    
    while True:
        # Generate random odd number of specified bit length
        candidate = random.getrandbits(bits)
        candidate |= (1 << bits - 1) | 1  # Set MSB and LSB to 1 (ensures odd and correct bit length)
        
        if is_prime_miller_rabin(candidate):
            print(f"Prime found: {candidate}")
            return candidate

def is_prime_miller_rabin(n, k=10):
    """
    Miller-Rabin primality test - probabilistic test for primality
    
    This test is much faster than trial division for large numbers
    It has a very low probability of false positives
    
    Args:
        n: Number to test for primality
        k: Number of rounds (more rounds = more accurate)
    
    Returns:
        True if n is probably prime, False if composite
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n-1 as d * 2^r (factoring out powers of 2)
    r = 0
    d = n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Perform k rounds of testing
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)  # a^d mod n
        
        if x == 1 or x == n - 1:
            continue
            
        for _ in range(r - 1):
            x = pow(x, 2, n)  # Square x
            if x == n - 1:
                break
        else:
            return False  # Composite
    return True  # Probably prime

# ============================================================================
# PART 2: PARAMETER GENERATION (SHARED BETWEEN BOTH PERSONS)
# ============================================================================

def generate_shared_parameters(key_length=2048):
    """
    Generate the public parameters that both persons will use
    
    In real-world scenarios, these are often standardized values
    that everyone agrees to use (like RFC 3526 groups)
    
    Args:
        key_length: Bit length of the prime modulus
    
    Returns:
        tuple: (p, g) where p is prime modulus and g is generator
    """
    print("=== GENERATING SHARED PARAMETERS ===")
    
    # Generate large prime p
    p = generate_random_prime(key_length)
    
    # Find generator g (simplified - using 2 for demonstration)
    # In practice, you should verify this is actually a generator
    g = find_generator(p)
    
    print(f"Shared prime p: {p}")
    print(f"Shared generator g: {g}")
    print("These parameters are public and known to everyone\n")
    
    return p, g

def find_generator(p):
    """
    Find a generator for the multiplicative group modulo p
    
    A generator g is a number where g^i mod p produces all values from 1 to p-1
    For simplicity, we use 2 (which works for many primes)
    
    Args:
        p: Prime modulus
    
    Returns:
        Generator value (simplified to 2 for this demo)
    """
    # Simplified: return 2 as generator
    # In production, you'd verify this generates the full group
    return 2

# ============================================================================
# PART 3: PERSON A'S KEY GENERATION
# ============================================================================

def personA_generate_private_key(p):
    """
    Person A generates their secret private key
    
    This is a random number between 2 and p-2
    This number must be kept secret and never shared
    
    Args:
        p: The shared prime modulus
    
    Returns:
        Person A's private key (integer)
    """
    print("=== PERSON A: GENERATING PRIVATE KEY ===")
    
    # Generate random private key in range [2, p-2]
    personA_private = random.randrange(2, p - 1)
    
    print(f"Person A's private key: {personA_private}")
    print("⚠️  This key must be kept SECRET!\n")
    
    return personA_private

def personA_generate_public_key(g, personA_private, p):
    """
    Person A generates their public key using their private key
    
    Public key = g^(private_key) mod p
    This is safe to share publicly due to discrete logarithm difficulty
    
    Args:
        g: Shared generator
        personA_private: Person A's private key
        p: Shared prime modulus
    
    Returns:
        Person A's public key (integer)
    """
    print("=== PERSON A: GENERATING PUBLIC KEY ===")
    
    # Calculate public key: g^private_key mod p
    personA_public = pow(g, personA_private, p)
    
    print(f"Person A's public key calculation: {g}^{personA_private} mod {p}")
    print(f"Person A's public key: {personA_public}")
    print("✅ This key can be shared publicly\n")
    
    return personA_public

# ============================================================================
# PART 4: PERSON B'S KEY GENERATION
# ============================================================================

def personB_generate_private_key(p):
    """
    Person B generates their secret private key
    
    This is independent of Person A's key generation
    Both persons generate their keys using the same method but different random values
    
    Args:
        p: The shared prime modulus
    
    Returns:
        Person B's private key (integer)
    """
    print("=== PERSON B: GENERATING PRIVATE KEY ===")
    
    # Generate random private key in range [2, p-2]
    personB_private = random.randrange(2, p - 1)
    
    print(f"Person B's private key: {personB_private}")
    print("⚠️  This key must be kept SECRET!\n")
    
    return personB_private

def personB_generate_public_key(g, personB_private, p):
    """
    Person B generates their public key using their private key
    
    Uses the same formula as Person A but with Person B's private key
    
    Args:
        g: Shared generator
        personB_private: Person B's private key
        p: Shared prime modulus
    
    Returns:
        Person B's public key (integer)
    """
    print("=== PERSON B: GENERATING PUBLIC KEY ===")
    
    # Calculate public key: g^private_key mod p
    personB_public = pow(g, personB_private, p)
    
    print(f"Person B's public key calculation: {g}^{personB_private} mod {p}")
    print(f"Person B's public key: {personB_public}")
    print("✅ This key can be shared publicly\n")
    
    return personB_public

# ============================================================================
# PART 5: PUBLIC KEY EXCHANGE (SIMULATION)
# ============================================================================

def simulate_public_key_exchange(personA_public, personB_public):
    """
    Simulate the exchange of public keys over an insecure channel
    
    In reality, this happens over the internet, email, or any communication method
    An eavesdropper can see these public keys, but that's okay!
    
    Args:
        personA_public: Person A's public key
        personB_public: Person B's public key
    
    Returns:
        tuple: (received keys for each person)
    """
    print("=== PUBLIC KEY EXCHANGE ===")
    print("📡 Person A sends their public key to Person B")
    print("📡 Person B sends their public key to Person A")
    print("👁️  An eavesdropper can see both public keys, but this is safe!")
    
    # Person A receives Person B's public key
    personA_received_public = personB_public
    # Person B receives Person A's public key  
    personB_received_public = personA_public
    
    print(f"Person A received: {personA_received_public}")
    print(f"Person B received: {personB_received_public}\n")
    
    return personA_received_public, personB_received_public

# ============================================================================
# PART 6: SHARED SECRET COMPUTATION
# ============================================================================

def personA_compute_shared_secret(personB_public, personA_private, p):
    """
    Person A computes the shared secret using Person B's public key and their own private key
    
    Shared Secret = (Person B's public key)^(Person A's private key) mod p
    
    Args:
        personB_public: Person B's public key (received during exchange)
        personA_private: Person A's private key (kept secret)
        p: Shared prime modulus
    
    Returns:
        Person A's computed shared secret
    """
    print("=== PERSON A: COMPUTING SHARED SECRET ===")
    
    # Calculate: (personB_public)^(personA_private) mod p
    personA_shared_secret = pow(personB_public, personA_private, p)
    
    print(f"Person A's calculation: {personB_public}^{personA_private} mod {p}")
    print(f"Person A's shared secret: {personA_shared_secret}")
    
    return personA_shared_secret

def personB_compute_shared_secret(personA_public, personB_private, p):
    """
    Person B computes the shared secret using Person A's public key and their own private key
    
    Shared Secret = (Person A's public key)^(Person B's private key) mod p
    
    Due to mathematical properties, this will equal Person A's computed secret!
    
    Args:
        personA_public: Person A's public key (received during exchange)
        personB_private: Person B's private key (kept secret)
        p: Shared prime modulus
    
    Returns:
        Person B's computed shared secret
    """
    print("=== PERSON B: COMPUTING SHARED SECRET ===")
    
    # Calculate: (personA_public)^(personB_private) mod p
    personB_shared_secret = pow(personA_public, personB_private, p)
    
    print(f"Person B's calculation: {personA_public}^{personB_private} mod {p}")
    print(f"Person B's shared secret: {personB_shared_secret}")
    
    return personB_shared_secret

# ============================================================================
# PART 7: SESSION KEY DERIVATION
# ============================================================================

def personA_derive_session_key(personA_shared_secret, key_length=32):
    """
    Person A derives a session key from the shared secret
    
    Uses SHA-256 hash function to convert the shared secret into a fixed-length key
    This key can then be used for symmetric encryption (AES, etc.)
    
    Args:
        personA_shared_secret: The computed shared secret
        key_length: Desired key length in bytes (32 = 256 bits)
    
    Returns:
        Person A's session key (bytes)
    """
    print("=== PERSON A: DERIVING SESSION KEY ===")
    
    # Convert shared secret to bytes and hash it
    secret_bytes = str(personA_shared_secret).encode('utf-8')
    hash_digest = hashlib.sha256(secret_bytes).digest()
    session_key = hash_digest[:key_length]
    
    print(f"Person A's session key (hex): {session_key.hex()}")
    
    return session_key

def personB_derive_session_key(personB_shared_secret, key_length=32):
    """
    Person B derives a session key from the shared secret
    
    Uses the same process as Person A - should produce identical key!
    
    Args:
        personB_shared_secret: The computed shared secret
        key_length: Desired key length in bytes (32 = 256 bits)
    
    Returns:
        Person B's session key (bytes)
    """
    print("=== PERSON B: DERIVING SESSION KEY ===")
    
    # Convert shared secret to bytes and hash it
    secret_bytes = str(personB_shared_secret).encode('utf-8')
    hash_digest = hashlib.sha256(secret_bytes).digest()
    session_key = hash_digest[:key_length]
    
    print(f"Person B's session key (hex): {session_key.hex()}")
    
    return session_key

# ============================================================================
# PART 8: VERIFICATION AND SECURITY ANALYSIS
# ============================================================================

def verify_shared_secrets(personA_secret, personB_secret):
    """
    Verify that both persons computed the same shared secret
    
    This is the magic of Diffie-Hellman: both parties arrive at the same secret
    without ever transmitting it!
    
    Args:
        personA_secret: Person A's computed shared secret
        personB_secret: Person B's computed shared secret
    
    Returns:
        Boolean indicating if secrets match
    """
    print("=== VERIFICATION ===")
    
    secrets_match = (personA_secret == personB_secret)
    
    print(f"Person A's shared secret: {personA_secret}")
    print(f"Person B's shared secret: {personB_secret}")
    print(f"✅ Secrets match: {secrets_match}")
    
    if secrets_match:
        print("🎉 SUCCESS! Both parties have the same shared secret!")
    else:
        print("❌ ERROR! Secrets don't match - something went wrong!")
    
    return secrets_match

def verify_session_keys(personA_key, personB_key):
    """
    Verify that both persons derived the same session key
    
    Args:
        personA_key: Person A's derived session key
        personB_key: Person B's derived session key
    
    Returns:
        Boolean indicating if keys match
    """
    print("=== SESSION KEY VERIFICATION ===")
    
    keys_match = (personA_key == personB_key)
    
    print(f"Person A's session key: {personA_key.hex()}")
    print(f"Person B's session key: {personB_key.hex()}")
    print(f"✅ Session keys match: {keys_match}")
    
    if keys_match:
        print("🔐 SUCCESS! Both parties can now use this key for secure communication!")
    else:
        print("❌ ERROR! Session keys don't match!")
    
    return keys_match

def explain_security(p, g, personA_public, personB_public, shared_secret):
    """
    Explain why Diffie-Hellman is secure
    
    Args:
        p, g: Public parameters
        personA_public, personB_public: Public keys
        shared_secret: The computed shared secret
    """
    print("\n=== SECURITY ANALYSIS ===")
    print("🔒 Why is this secure?")
    print(f"   • Public information known to eavesdropper:")
    print(f"     - Prime p: {p}")
    print(f"     - Generator g: {g}")
    print(f"     - Person A's public key: {personA_public}")
    print(f"     - Person B's public key: {personB_public}")
    print(f"   • Secret information (unknown to eavesdropper):")
    print(f"     - Person A's private key: HIDDEN")
    print(f"     - Person B's private key: HIDDEN")
    print(f"     - Shared secret: {shared_secret}")
    print(f"   • To break this, an attacker would need to solve the discrete logarithm problem:")
    print(f"     - Given g^x mod p, find x")
    print(f"     - This is computationally infeasible for large primes")
    print(f"   • Even with quantum computers, this would take significant time for 2048+ bit keys")

# ============================================================================
# PART 9: COMPLETE DEMONSTRATION
# ============================================================================

def demonstrate_full_diffie_hellman():
    """
    Complete demonstration of the Diffie-Hellman key exchange
    Shows each step with detailed explanations
    """
    print("🔐 DIFFIE-HELLMAN KEY EXCHANGE DEMONSTRATION 🔐")
    print("=" * 60)
    
    # Step 1: Generate shared parameters
    p, g = generate_shared_parameters(key_length=1024)  # Using 1024 for demo speed
    
    # Step 2: Person A generates their keys
    personA_private = personA_generate_private_key(p)
    personA_public = personA_generate_public_key(g, personA_private, p)
    
    # Step 3: Person B generates their keys
    personB_private = personB_generate_private_key(p)
    personB_public = personB_generate_public_key(g, personB_private, p)
    
    # Step 4: Exchange public keys
    personA_received, personB_received = simulate_public_key_exchange(personA_public, personB_public)
    
    # Step 5: Compute shared secrets
    personA_shared = personA_compute_shared_secret(personB_received, personA_private, p)
    personB_shared = personB_compute_shared_secret(personA_received, personB_private, p)
    
    # Step 6: Derive session keys
    personA_session_key = personA_derive_session_key(personA_shared)
    personB_session_key = personB_derive_session_key(personB_shared)
    
    # Step 7: Verify everything worked
    verify_shared_secrets(personA_shared, personB_shared)
    verify_session_keys(personA_session_key, personB_session_key)
    
    # Step 8: Explain security
    explain_security(p, g, personA_public, personB_public, personA_shared)
    
    print("\n" + "=" * 60)
    print("🎯 SUMMARY:")
    print("1. Both parties now have the same secret key")
    print("2. This key was never transmitted over the network")
    print("3. An eavesdropper cannot compute the key from public information")
    print("4. The key can now be used for symmetric encryption (AES, etc.)")

# Run the demonstration
if __name__ == "__main__":
    demonstrate_full_diffie_hellman()