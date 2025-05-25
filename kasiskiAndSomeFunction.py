import re
import math
from collections import Counter, defaultdict
from itertools import combinations
import base64
from binascii import hexlify, unhexlify


class CryptanalysisTools:
    def __init__(self):
        # Fréquences théoriques des lettres en français
        self.french_frequencies = {
            'A': 0.0811, 'B': 0.0081, 'C': 0.0338, 'D': 0.0428, 'E': 0.1210,
            'F': 0.0111, 'G': 0.0089, 'H': 0.0061, 'I': 0.0723, 'J': 0.0056,
            'K': 0.0001, 'L': 0.0549, 'M': 0.0262, 'N': 0.0715, 'O': 0.0530,
            'P': 0.0317, 'Q': 0.0008, 'R': 0.0655, 'S': 0.0808, 'T': 0.0707,
            'U': 0.0574, 'V': 0.0132, 'W': 0.0004, 'X': 0.0045, 'Y': 0.0030,
            'Z': 0.0006
        }
        
        # Fréquences théoriques des lettres en anglais
        self.english_frequencies = {
            'A': 0.0812, 'B': 0.0149, 'C': 0.0278, 'D': 0.0425, 'E': 0.1202,
            'F': 0.0223, 'G': 0.0202, 'H': 0.0609, 'I': 0.0697, 'J': 0.0015,
            'K': 0.0077, 'L': 0.0403, 'M': 0.0241, 'N': 0.0675, 'O': 0.0751,
            'P': 0.0193, 'Q': 0.0010, 'R': 0.0599, 'S': 0.0633, 'T': 0.0906,
            'U': 0.0276, 'V': 0.0098, 'W': 0.0236, 'X': 0.0015, 'Y': 0.0197,
            'Z': 0.0007
        }

    def clean_text(self, text):
        """Nettoie le texte en gardant seulement les lettres et en convertissant en majuscules"""
        return re.sub(r'[^A-Za-z]', '', text).upper()

    def find_repeated_sequences(self, text, min_length=3, max_length=10):
        """Trouve les séquences répétées dans le texte"""
        text = self.clean_text(text)
        sequences = {}
        
        for length in range(min_length, min_length + max_length - min_length + 1):
            for i in range(len(text) - length + 1):
                sequence = text[i:i + length]
                if sequence in sequences:
                    sequences[sequence].append(i)
                else:
                    sequences[sequence] = [i]
        
        # Filtrer pour garder seulement les séquences qui apparaissent au moins 2 fois
        repeated_sequences = {seq: positions for seq, positions in sequences.items() 
                            if len(positions) >= 2}
        
        return repeated_sequences

    def calculate_distances(self, positions):
        """Calcule les distances entre les positions d'une séquence répétée"""
        distances = []
        for i in range(len(positions)):
            for j in range(i + 1, len(positions)):
                distances.append(positions[j] - positions[i])
        return distances

    def gcd(self, a, b):
        """Calcule le plus grand commun diviseur"""
        while b:
            a, b = b, a % b
        return a

    def gcd_multiple(self, numbers):
        """Calcule le PGCD de plusieurs nombres"""
        if not numbers:
            return 0
        result = numbers[0]
        for i in range(1, len(numbers)):
            result = self.gcd(result, numbers[i])
        return result

    def prime_factors(self, n):
        """Trouve les facteurs premiers d'un nombre"""
        factors = []
        d = 2
        while d * d <= n:
            while n % d == 0:
                factors.append(d)
                n //= d
            d += 1
        if n > 1:
            factors.append(n)
        return factors

    def kasiski_test(self, ciphertext, min_seq_length=3, max_seq_length=6):
        """Effectue le test de Kasiski pour estimer la longueur de la clé"""
        print("🔍 **Analyse de Kasiski en cours...**")
        
        # Nettoyer le texte
        clean_cipher = self.clean_text(ciphertext)
        print(f"📝 Texte nettoyé ({len(clean_cipher)} caractères): {clean_cipher[:50]}...")
        
        # Trouver les séquences répétées
        repeated_sequences = self.find_repeated_sequences(clean_cipher, min_seq_length, max_seq_length)
        
        if not repeated_sequences:
            print("❌ Aucune séquence répétée trouvée.")
            return None
        
        print(f"\n📊 **{len(repeated_sequences)} séquences répétées trouvées:**")
        
        all_distances = []
        sequence_data = []
        
        for sequence, positions in repeated_sequences.items():
            if len(positions) >= 2:
                distances = self.calculate_distances(positions)
                all_distances.extend(distances)
                
                sequence_info = {
                    'sequence': sequence,
                    'positions': positions,
                    'distances': distances,
                    'occurrences': len(positions)
                }
                sequence_data.append(sequence_info)
        
        # Trier par nombre d'occurrences décroissant
        sequence_data.sort(key=lambda x: x['occurrences'], reverse=True)
        
        # Afficher les séquences les plus importantes
        for i, data in enumerate(sequence_data[:10]):  # Top 10
            print(f"  {i+1}. '{data['sequence']}' - {data['occurrences']} occurrences")
            print(f"     Positions: {data['positions']}")
            print(f"     Distances: {data['distances']}")
            
            # Facteurs des distances
            factors = []
            for distance in data['distances']:
                factors.extend(self.prime_factors(distance))
            
            if factors:
                factor_count = Counter(factors)
                print(f"     Facteurs principaux: {dict(factor_count.most_common(5))}")
            print()
        
        # Analyse globale des distances
        if all_distances:
            print("📈 **Analyse globale des distances:**")
            distance_counter = Counter(all_distances)
            print(f"   Distances les plus fréquentes: {dict(distance_counter.most_common(10))}")
            
            # Facteurs de toutes les distances
            all_factors = []
            for distance in all_distances:
                all_factors.extend(self.prime_factors(distance))
            
            factor_counter = Counter(all_factors)
            print(f"   Facteurs les plus fréquents: {dict(factor_counter.most_common(10))}")
            
            # PGCD des distances
            gcd_result = self.gcd_multiple(all_distances)
            print(f"   PGCD de toutes les distances: {gcd_result}")
            
            # Estimation de la longueur de clé
            probable_key_lengths = []
            for factor, count in factor_counter.most_common(10):
                if factor > 1 and count >= 2:  # Facteur apparaissant au moins 2 fois
                    probable_key_lengths.append((factor, count))
            
            print(f"\n🔑 **Longueurs de clé probables:**")
            for length, frequency in probable_key_lengths:
                print(f"   Longueur {length}: apparaît {frequency} fois dans les facteurs")
            
            return probable_key_lengths
        
        return None

    def calculate_index_of_coincidence(self, text):
        """Calcule l'indice de coïncidence d'un texte"""
        text = self.clean_text(text)
        n = len(text)
        
        if n <= 1:
            return 0
        
        # Compter les fréquences de chaque lettre
        letter_counts = Counter(text)
        
        # Calculer l'IC
        ic = 0
        for count in letter_counts.values():
            ic += count * (count - 1)
        
        ic = ic / (n * (n - 1))
        return ic

    def split_text_by_key_length(self, text, key_length):
        """Divise le texte en groupes selon la longueur de clé supposée"""
        text = self.clean_text(text)
        groups = [[] for _ in range(key_length)]
        
        for i, char in enumerate(text):
            groups[i % key_length].append(char)
        
        return [''.join(group) for group in groups]

    def analyze_ic_for_key_length(self, ciphertext, key_length):
        """Analyse l'IC pour une longueur de clé donnée"""
        groups = self.split_text_by_key_length(ciphertext, key_length)
        ics = []
        
        for i, group in enumerate(groups):
            if len(group) > 1:
                ic = self.calculate_index_of_coincidence(group)
                ics.append(ic)
            else:
                ics.append(0)
        
        average_ic = sum(ics) / len(ics) if ics else 0
        return ics, average_ic

    def test_multiple_key_lengths(self, ciphertext, max_key_length=20):
        """Teste plusieurs longueurs de clé possibles avec l'IC"""
        print("📊 **Analyse par Indice de Coïncidence:**")
        
        clean_cipher = self.clean_text(ciphertext)
        overall_ic = self.calculate_index_of_coincidence(clean_cipher)
        
        print(f"📝 Texte analysé: {len(clean_cipher)} caractères")
        print(f"🔢 IC global du texte: {overall_ic:.4f}")
        print(f"📚 IC théorique français: ~0.0778")
        print(f"🌍 IC théorique anglais: ~0.0667")
        print(f"🎲 IC théorique aléatoire: ~0.0385")
        
        results = []
        
        print(f"\n📈 **Test des longueurs de clé de 1 à {max_key_length}:**")
        print("Longueur | IC Moyen | IC par groupe")
        print("-" * 50)
        
        for key_length in range(1, max_key_length + 1):
            group_ics, average_ic = self.analyze_ic_for_key_length(clean_cipher, key_length)
            results.append((key_length, average_ic, group_ics))
            
            # Formatage pour l'affichage
            ics_str = " ".join([f"{ic:.3f}" for ic in group_ics[:8]])  # Limiter à 8 groupes pour l'affichage
            if len(group_ics) > 8:
                ics_str += "..."
            
            print(f"{key_length:8d} | {average_ic:8.4f} | {ics_str}")
        
        # Trier par IC moyen décroissant
        results.sort(key=lambda x: x[1], reverse=True)
        
        print(f"\n🏆 **Top 5 des longueurs de clé les plus probables:**")
        for i, (key_length, avg_ic, group_ics) in enumerate(results[:5]):
            print(f"{i+1}. Longueur {key_length}: IC moyen = {avg_ic:.4f}")
            if key_length <= 10:  # Détails seulement pour les clés courtes
                for j, ic in enumerate(group_ics):
                    print(f"   Groupe {j+1}: {ic:.4f}")
        
        return results

    def frequency_analysis(self, text, language='french'):
        """Analyse de fréquence des lettres"""
        text = self.clean_text(text)
        n = len(text)
        
        if n == 0:
            return {}, 0
        
        # Compter les fréquences
        letter_counts = Counter(text)
        frequencies = {letter: count/n for letter, count in letter_counts.items()}
        
        # Choisir les fréquences théoriques
        theoretical_freq = self.french_frequencies if language == 'french' else self.english_frequencies
        
        # Calculer le chi-carré
        chi_squared = 0
        for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
            observed = frequencies.get(letter, 0)
            expected = theoretical_freq.get(letter, 0)
            if expected > 0:
                chi_squared += ((observed - expected) ** 2) / expected
        
        return frequencies, chi_squared

    def comprehensive_analysis(self, ciphertext, max_key_length=15):
        """Analyse complète combinant Kasiski et IC"""
        print("🔬 **ANALYSE CRYPTANALYTIQUE COMPLÈTE**")
        print("=" * 60)
        
        # Test de Kasiski
        print("\n1️⃣ **TEST DE KASISKI**")
        kasiski_results = self.kasiski_test(ciphertext)
        
        # Test d'IC
        print("\n2️⃣ **ANALYSE PAR INDICE DE COÏNCIDENCE**")
        ic_results = self.test_multiple_key_lengths(ciphertext, max_key_length)
        
        # Synthèse
        print("\n3️⃣ **SYNTHÈSE ET RECOMMANDATIONS**")
        
        if kasiski_results:
            kasiski_lengths = [length for length, _ in kasiski_results[:5]]
            print(f"🔍 Kasiski suggère: {kasiski_lengths}")
        
        ic_top_lengths = [length for length, _, _ in ic_results[:5]]
        print(f"📊 IC suggère: {ic_top_lengths}")
        
        # Intersection des résultats
        if kasiski_results:
            common_lengths = set(kasiski_lengths) & set(ic_top_lengths)
            if common_lengths:
                print(f"✅ Longueurs confirmées par les deux méthodes: {sorted(common_lengths)}")
            else:
                print("⚠️  Aucune longueur confirmée par les deux méthodes")
        
        # Recommandations finales
        print(f"\n🎯 **RECOMMANDATIONS:**")
        best_candidates = ic_results[:3]
        for i, (length, avg_ic, _) in enumerate(best_candidates):
            status = ""
            if kasiski_results and length in [l for l, _ in kasiski_results[:3]]:
                status = " ✅ (confirmé par Kasiski)"
            print(f"{i+1}. Essayer longueur de clé {length} (IC={avg_ic:.4f}){status}")
        
        return ic_results, kasiski_results


def print_banner():
    print("=" * 70)
    print("      🔐 OUTILS D'ANALYSE CRYPTOGRAPHIQUE 🔐")
    print("           Test de Kasiski & Indice de Coïncidence")
    print("=" * 70)
    print()


def get_user_input():
    """Interface utilisateur pour choisir l'action"""
    print("🎯 **Choisissez une analyse:**")
    print("1. 🔍 Test de Kasiski seulement")
    print("2. 📊 Indice de Coïncidence seulement") 
    print("3. 🔬 Analyse complète (Kasiski + IC)")
    print("4. 📈 Analyse de fréquence")
    print("5. 🎲 Générer un exemple de texte chiffré")
    print("6. ❌ Quitter")
    print()
    
    choice = input("Votre choix (1-6): ").strip()
    return choice


def get_ciphertext():
    """Récupère le texte chiffré de l'utilisateur"""
    print("\n📝 **Saisie du texte chiffré:**")
    print("Vous pouvez:")
    print("1. Taper directement le texte")
    print("2. Coller un texte long")
    print()
    
    ciphertext = input("Entrez le texte chiffré: ").strip()
    
    if not ciphertext:
        print("❌ Erreur: Le texte ne peut pas être vide.")
        return None
    
    print(f"✅ Texte reçu: {len(ciphertext)} caractères")
    print(f"Aperçu: {ciphertext[:100]}{'...' if len(ciphertext) > 100 else ''}")
    
    return ciphertext


def kasiski_analysis_only(tools):
    """Interface pour le test de Kasiski seulement"""
    ciphertext = get_ciphertext()
    if not ciphertext:
        return
    
    print(f"\n⚙️ **Paramètres du test de Kasiski:**")
    try:
        min_length = int(input("Longueur minimale des séquences (défaut: 3): ") or "3")
        max_length = int(input("Longueur maximale des séquences (défaut: 6): ") or "6")
    except ValueError:
        print("⚠️ Valeurs invalides, utilisation des valeurs par défaut.")
        min_length, max_length = 3, 6
    
    print("\n" + "="*60)
    results = tools.kasiski_test(ciphertext, min_length, max_length)
    
    if results:
        print(f"\n💡 **Conclusion:**")
        best_length = results[0][0]
        print(f"La longueur de clé la plus probable est: {best_length}")
    else:
        print(f"\n❌ **Conclusion:**")
        print("Impossible de déterminer la longueur de clé avec cette méthode.")


def ic_analysis_only(tools):
    """Interface pour l'IC seulement"""
    ciphertext = get_ciphertext()
    if not ciphertext:
        return
    
    print(f"\n⚙️ **Paramètres de l'analyse IC:**")
    try:
        max_length = int(input("Longueur maximale de clé à tester (défaut: 20): ") or "20")
    except ValueError:
        print("⚠️ Valeur invalide, utilisation de la valeur par défaut.")
        max_length = 20
    
    print("\n" + "="*60)
    results = tools.test_multiple_key_lengths(ciphertext, max_length)
    
    print(f"\n💡 **Conclusion:**")
    best_length, best_ic, _ = results[0]
    print(f"La longueur de clé la plus probable est: {best_length} (IC={best_ic:.4f})")


def complete_analysis(tools):
    """Interface pour l'analyse complète"""
    ciphertext = get_ciphertext()
    if not ciphertext:
        return
    
    print(f"\n⚙️ **Paramètres de l'analyse:**")
    try:
        max_length = int(input("Longueur maximale de clé à tester (défaut: 15): ") or "15")
    except ValueError:
        print("⚠️ Valeur invalide, utilisation de la valeur par défaut.")
        max_length = 15
    
    print("\n" + "="*70)
    ic_results, kasiski_results = tools.comprehensive_analysis(ciphertext, max_length)


def frequency_analysis(tools):
    """Interface pour l'analyse de fréquence"""
    ciphertext = get_ciphertext()
    if not ciphertext:
        return
    
    print(f"\n🌍 **Choisissez la langue de référence:**")
    print("1. Français")
    print("2. Anglais")
    
    lang_choice = input("Votre choix (1-2): ").strip()
    language = 'french' if lang_choice == '1' else 'english'
    
    print(f"\n📊 **Analyse de fréquence ({language}):**")
    
    clean_text = tools.clean_text(ciphertext)
    frequencies, chi_squared = tools.frequency_analysis(clean_text, language)
    
    print(f"Texte analysé: {len(clean_text)} caractères")
    print(f"Chi-carré: {chi_squared:.4f}")
    
    # Afficher les fréquences observées vs théoriques
    print(f"\n📈 **Fréquences observées vs théoriques:**")
    print("Lettre | Observé | Théorique | Différence")
    print("-" * 45)
    
    theoretical_freq = tools.french_frequencies if language == 'french' else tools.english_frequencies
    
    for letter in sorted(frequencies.keys()):
        observed = frequencies[letter]
        theoretical = theoretical_freq.get(letter, 0)
        diff = abs(observed - theoretical)
        print(f"  {letter}    | {observed:6.3f}  |  {theoretical:6.3f}   | {diff:6.3f}")


def generate_example():
    """Génère un exemple de texte chiffré par Vigenère"""
    print(f"\n🎲 **Génération d'un exemple:**")
    
    # Exemple de texte chiffré par Vigenère
    examples = [
        {
            'text': "LXFOPVEFRNHRJFDRPBLZABLFGQRZYXOUBMZKLOKWJYMMAJFXNPXCMNNYLZJDLLGGHXICMHBZPKGZRRFLMRGQKJHRJFQVNOZZKRWKWTJHULNHHLXTFMWRCBKLOKJYXJDLLHGHRCLXJRFHBNNXODFSTXXCZALXJXJDLLBHRKJYXJLGHXOQGJXFQFHHJFLGOXRFLFLGNFRNHZGJHSHDOLRHZFGHZAOLOKJGNCMRJQRFLCBBZOULFKJJLLXJLKXKRFXZNRJLLGOBQSFLBWJKGJHZRHHZAJKCMHHLHQNQFFXGHXOPJNMLKPJDLLDLHHLLBZJNOYXRXHQRJFXKJNKGKKBXRJFCQMHLLGZMNHQLQXJFHTFJFGJGNQJSKCDFRKSJHKKDKJHOJXFTRXLKGHNJJSLLGNJGJJRZJGJJTZPKJGGLKVZRFHHQJDHGHHGJJZNZFHHGJJXHQRKFLQHJSKLZSHHCMHBZGGJJZNZFKMGJYFZJDFZJJVNXKQSQFLZJQGHXBMHBRJFQVLMKXJFLHGHRCLXJMHQQLRXJFBJSQRQKBBXRJFCQMHLLBOSMZNJJQBLNNCSHHQBJSRZYBJNKYHLDDQZBMHBZMMAJFXMRLGOXRFLFLXFRXLQVGKRJJTJXJMFGGHXOQGJXFLMRGQKGNCMRJCBBZFRHZGFNYJMHQQLRFLXFRXLQVGKRJYSGGSJQZJHYKGJGXNLGJXZFQGJGTJXJHKJNXHMXRJGGFMLRSAQJFXKLOKJGNCMRJQRFLCBBZJKLRDDGGJQHMQGKXJZNRJLFBJHJGLXJXHQHNRJFNZSJBSCZJXJDLLBWJZJHBRJFGQJYKHLNOZSSQXJFKGJJJDHLYJJGZJQWJFYZHLNNAQBLFZJXCQNMLKZGTJGHRRZJQJDLQBCJKXJXJFLHBLLHQNLGQJQBLLHGQJGLBHJMJKLXNRGSQFNQSJGLHZQRJSJGFGJJKZFGFGJHZFXHQLZHQRJFGNFHJQLLHLHQKHLQJJXJDLLBHLZLNHHRXJFTHHJJJLMMLJKXJGFZJJRFMJHLZFGNZGJZNQJLKGJJCQJLKJDHGJGRJJDZRZFKMGJYJFGZGFNYZGLHHQRJFGHJFGHZAOLOKJGNCMRJQRFLFZDJVKGJSJHKZGFRZMHRRGQKZGTJGHRRZJQJDLQBCJKXJGMLRSAQJFXZGJXXJFGJYNQSJGLQJQBLNHKSDRKZGTJRGNFRNHQJKJQFXMRLGOXRFLFLQGKZPXBLJHKSQZJXBHCMHHLGFGJJZGFXCZGLHZRQKJHRJFQVNOZZKFRHZJXHQRXJGHXOQGJXFQHCMHHJQBLNHKSDRKZGTJRGNFRNHQJK",
            'key': 'CRYPTO',
            'description': 'Texte chiffré avec la clé "CRYPTO" (longueur 6)'
        },
        {
            'text': "RIJVSUYVJN RIJVS UYVJN RIJVSUYVJN RIJVS UYVJN RIJVSUYVJN",
            'key': 'SECRET',
            'description': 'Exemple simple avec répétitions (clé "SECRET", longueur 6)'
        }
    ]
    
    print("Exemples disponibles:")
    for i, example in enumerate(examples):
        print(f"{i+1}. {example['description']}")
    
    try:
        choice = int(input("\nChoisissez un exemple (1-2): ")) - 1
        if 0 <= choice < len(examples):
            example = examples[choice]
            print(f"\n📋 **Texte d'exemple généré:**")
            print(f"Clé utilisée: {example['key']}")
            print(f"Longueur de clé: {len(example['key'])}")
            print(f"Texte chiffré:\n{example['text']}")
            print(f"\n💡 Vous pouvez copier ce texte pour le tester avec les autres options.")
        else:
            print("❌ Choix invalide.")
    except ValueError:
        print("❌ Choix invalide.")


def kasiski_main():
    """Fonction principale"""
    tools = CryptanalysisTools()
    
    while True:
        print_banner()
        choice = get_user_input()
        
        if choice == "1":
            kasiski_analysis_only(tools)
        elif choice == "2":
            ic_analysis_only(tools)
        elif choice == "3":
            complete_analysis(tools)
        elif choice == "4":
            frequency_analysis(tools)
        elif choice == "5":
            generate_example()
        elif choice == "6":
            print("👋 Au revoir!")
            break
        else:
            print("❌ Choix invalide. Veuillez choisir entre 1 et 6.")
        
        input("\n⏸️  Appuyez sur Entrée pour continuer...")
        print("\n" * 2)

