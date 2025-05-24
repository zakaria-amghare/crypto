import random
import math

def miller_rabin_test(n, k=20):
    """
    Test de primalité de Miller-Rabin
    n: nombre à tester
    k: nombre d'itérations (plus k est grand, plus le test est précis)
    """
    if n == 2 or n == 3:
        return True
    if n < 2 or n % 2 == 0:
        return False
    
    # Écrire n-1 comme d * 2^r
    r = 0
    d = n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Effectuer k tours de test
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)  # a^d mod n
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True

def is_prime(n):
    """
    Vérification de primalité combinant tests simples et Miller-Rabin
    """
    # Tests de base
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    
    # Test de divisibilité par les premiers petits nombres
    small_primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False
    
    # Test de Miller-Rabin
    return miller_rabin_test(n)

def generate_512_bit_prime():
    """
    Génère un nombre premier de 512 bits
    """
    # Limites pour un nombre de 512 bits
    min_val = 2**511          # Plus petit nombre de 512 bits
    max_val = 2**512 - 1      # Plus grand nombre de 512 bits
    
    attempts = 0
    
    while True:
        attempts += 1
        
        # Générer un nombre aléatoire impair dans la plage
        candidate = random.randrange(min_val, max_val + 1)
        
        # S'assurer que le nombre est impair
        if candidate % 2 == 0:
            candidate += 1
        
        # Vérifier qu'il est toujours dans la plage après ajustement
        if candidate > max_val:
            continue
        
        # Tester la primalité
        if is_prime(candidate):
            print(f"Nombre premier trouvé après {attempts} tentatives")
            return candidate

def verify_bit_length(n):
    """
    Vérifie que le nombre a exactement 512 bits
    """
    return n.bit_length() == 512

def generate_2048_bit_prime():
    """
    Génère un nombre premier de 2048 bits
    """
    min_val = 2**2047
    max_val = 2**2048 - 1
    
    attempts = 0
    while True:
        attempts += 1
        candidate = random.randrange(min_val, max_val + 1)
        if candidate % 2 == 0:
            candidate += 1
        if candidate > max_val:
            continue
        if is_prime(candidate):
            print(f"Nombre premier de 2048 bits trouvé après {attempts} tentatives")
            return candidate