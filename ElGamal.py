import random
from random_prime import *


def find_primitive_root(prime):
    """
    Trouve un générateur (racine primitive) modulo prime
    """
    if prime == 2:
        return 1
    
    print("Recherche du générateur...")
    
    # Factoriser p-1
    phi = prime - 1
    factors = []
    n = phi
    
    # Trouver tous les facteurs premiers de phi
    d = 2
    while d * d <= n:
        while n % d == 0:
            factors.append(d)
            n //= d
        d += 1
    if n > 1:
        factors.append(n)
    
    # Supprimer les doublons
    factors = list(set(factors))
    
    # Tester les candidats pour le générateur
    for g in range(2, min(prime, 1000)):  # Limiter la recherche pour éviter la lenteur
        is_generator = True
        for factor in factors:
            if pow(g, phi // factor, prime) == 1:
                is_generator = False
                break
        
        if is_generator:
            print(f"Générateur trouvé: {g}")
            return g
    
    # Si aucun générateur n'est trouvé rapidement, utiliser 2 (souvent valide)
    print("Utilisation de g=2 comme générateur")
    return 2

def generate_elgamal_keys():
    """
    Génère les clés publiques et privées ElGamal
    Retourne: (clé_publique, clé_privée)
    """
    print("=== GÉNÉRATION DES CLÉS ELGAMAL ===")
    
    # Étape 1: Générer un nombre premier p de 2048 bits
    print("1. Génération du nombre premier p de 2048 bits...")
    p = generate_2048_bit_prime()
    print(f"   p = {p}")
    
    # Étape 2: Trouver un générateur g
    print("2. Recherche du générateur g...")
    g = find_primitive_root(p)
    print(f"   g = {g}")
    
    # Étape 3: Générer la clé privée x
    print("3. Génération de la clé privée x...")
    x = random.randrange(1, p - 1)
    print(f"   x = {x}")
    
    # Étape 4: Calculer la clé publique y = g^x mod p
    print("4. Calcul de la clé publique y = g^x mod p...")
    y = pow(g, x, p)
    print(f"   y = {y}")
    
    public_key = (p, g, y)
    private_key = (p, x)
    
    print("Génération des clés terminée!\n")
    
    return public_key, private_key

def elgamal_encrypt(message, public_key):
    """
    Chiffre un message avec ElGamal
    message: string ou entier à chiffrer
    public_key: (p, g, y)
    Retourne: (c1, c2)
    """
    p, g, y = public_key
    
    print("=== CHIFFREMENT ELGAMAL ===")
    
    # Convertir le message en entier si nécessaire
    if isinstance(message, str):
        message_bytes = message.encode('utf-8')
        m = int.from_bytes(message_bytes, 'big')
        print(f"1. Message '{message}' converti en entier: {m}")
    else:
        m = message
        print(f"1. Message (entier): {m}")
    
    # Vérifier que le message est plus petit que p
    if m >= p:
        raise ValueError("Le message est trop long pour cette taille de clé")
    
    # Étape 1: Générer un nombre aléatoire k
    k = random.randrange(1, p - 1)
    print(f"2. Nombre aléatoire k généré: {k}")
    
    # Étape 2: Calculer c1 = g^k mod p
    c1 = pow(g, k, p)
    print(f"3. c1 = g^k mod p = {c1}")
    
    # Étape 3: Calculer c2 = m * y^k mod p
    c2 = (m * pow(y, k, p)) % p
    print(f"4. c2 = m * y^k mod p = {c2}")
    
    print("Chiffrement terminé!\n")
    
    return (c1, c2)

def elgamal_decrypt(ciphertext, private_key):
    """
    Déchiffre un message avec ElGamal
    ciphertext: (c1, c2)
    private_key: (p, x)
    Retourne: message déchiffré
    """
    p, x = private_key
    c1, c2 = ciphertext
    
    print("=== DÉCHIFFREMENT ELGAMAL ===")
    print(f"1. Texte chiffré reçu: c1={c1}, c2={c2}")
    
    # Étape 1: Calculer s = c1^x mod p
    s = pow(c1, x, p)
    print(f"2. s = c1^x mod p = {s}")
    
    # Étape 2: Calculer l'inverse modulaire de s
    s_inv = pow(s, p - 2, p)  # Utilise le petit théorème de Fermat
    print(f"3. s^(-1) mod p = {s_inv}")
    
    # Étape 3: Calculer m = c2 * s^(-1) mod p
    m = (c2 * s_inv) % p
    print(f"4. Message déchiffré (entier): {m}")
    
    # Convertir l'entier en texte si possible
    try:
        # Calculer le nombre d'octets nécessaires
        if m == 0:
            message = ""
        else:
            byte_length = (m.bit_length() + 7) // 8
            message_bytes = m.to_bytes(byte_length, 'big')
            message = message_bytes.decode('utf-8')
        print(f"5. Message déchiffré (texte): '{message}'")
        print("Déchiffrement terminé!\n")
        return message
    except:
        print("5. Impossible de décoder en texte, retour de l'entier")
        print("Déchiffrement terminé!\n")
        return m

def demonstrate_elgamal():
    """
    Démonstration complète de l'algorithme ElGamal
    """
    print("=== DÉMONSTRATION COMPLÈTE ELGAMAL 2048 BITS ===\n")
    
    # Génération des clés
    public_key, private_key = generate_elgamal_keys()
    
    print("RÉSUMÉ DES CLÉS:")
    print(f"Clé publique (p, g, y): {public_key}")
    print(f"Clé privée (p, x): {private_key}\n")
    
    # Test avec un message
    message = "Hello ElGamal 2048!"
    print(f"MESSAGE ORIGINAL: '{message}'\n")
    
    # Chiffrement
    ciphertext = elgamal_encrypt(message, public_key)
    print(f"MESSAGE CHIFFRÉ: {ciphertext}\n")
    
    # Déchiffrement
    decrypted_message = elgamal_decrypt(ciphertext, private_key)
    print(f"MESSAGE FINAL: '{decrypted_message}'\n")
    
    # Vérification
    if message == decrypted_message:
        print("✅ SUCCESS: Le message a été correctement chiffré et déchiffré!")
    else:
        print("❌ ERROR: Erreur dans le processus!")
    
    return public_key, private_key

def test_elgamal_with_custom_message():
    """
    Test ElGamal avec un message personnalisé
    """
    print("\n=== TEST AVEC MESSAGE PERSONNALISÉ ===")
    
    # Générer les clés
    public_key, private_key = generate_elgamal_keys()
    
    # Message personnalisé
    custom_message = input("Entrez votre message à chiffrer: ")
    
    # Chiffrement
    encrypted = elgamal_encrypt(custom_message, public_key)
    print(f"Votre message chiffré: {encrypted}")
    
    # Déchiffrement
    decrypted = elgamal_decrypt(encrypted, private_key)
    print(f"Votre message déchiffré: '{decrypted}'")
    
    return encrypted, decrypted

def main_ELGamal():
    """
    Fonction principale avec menu de choix
    """
    print("ALGORITHME ELGAMAL 2048 BITS")
    print("1. Démonstration complète")
    print("2. Test avec message personnalisé")
    print("3. Génération de clés seulement")
    
    choice = input("Votre choix (1/2/3): ")
    
    if choice == "1":
        demonstrate_elgamal()
    elif choice == "2":
        test_elgamal_with_custom_message()
    elif choice == "3":
        public_key, private_key = generate_elgamal_keys()
        print(f"Clés générées avec succès!")
    else:
        print("Choix invalide, lancement de la démonstration par défaut...")
        demonstrate_elgamal()

main_ELGamal()