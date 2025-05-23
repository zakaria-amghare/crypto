from collections import defaultdict, Counter

def find_repeated_sequences(ciphertext, min_seq_length=3):
    """
    Finds all repeated sequences of a given minimum length in the ciphertext.
    Returns a dictionary with the sequence as the key and a list of starting indices as the value.
    """
    repeated_seq_positions = defaultdict(list)
    for i in range(len(ciphertext) - min_seq_length + 1):
        seq = ciphertext[i:i+min_seq_length]
        repeated_seq_positions[seq].append(i)
    # Only keep sequences that occur more than once.
    repeated_seq_positions = {seq: positions 
                              for seq, positions in repeated_seq_positions.items() 
                              if len(positions) > 1}
    return repeated_seq_positions

def find_factors(n):
    """
    Returns a list of factors (greater than 1) for a given number n.
    """
    factors = []
    for i in range(2, n+1):
        if n % i == 0:
            factors.append(i)
    return factors

def kasiski_examination(ciphertext, min_seq_length=3):
    """
    Performs the Kasiski examination on the provided ciphertext.
    
    Steps:
      1. Finds repeated sequences in the ciphertext.
      2. Computes the distances between consecutive occurrences of each repeated sequence.
      3. Factors each distance to find common factors that may suggest the key length.
    
    Returns:
      - repeated_seq: Dictionary of repeated sequences and their positions.
      - distances: List of distances between repeated sequence occurrences.
      - factor_counts: A Counter object tallying the frequency of each factor.
    """
    repeated_seq = find_repeated_sequences(ciphertext, min_seq_length)
    distances = []
    
    # Compute distances between consecutive occurrences of each repeated sequence.
    for seq, positions in repeated_seq.items():
        if len(positions) > 1:
            for i in range(len(positions) - 1):
                distance = positions[i+1] - positions[i]
                distances.append(distance)
    
    # Count factors (other than 1) for each distance.
    factor_counts = Counter()
    for d in distances:
        for factor in find_factors(d):
            factor_counts[factor] += 1
            
    return repeated_seq, distances, factor_counts

# Example usage:
if __name__ == '__main__':
    # Example ciphertext (modify with your ciphertext)
    ciphertext = "LQYHTKIIZZLSRPAEKJUIMTQVLUMINFKNACIMQTAEEXRMOUEIPABKYTVHIZLVRDETUUUSJINEOILVWCQWBITSMBXVMVXLMXLPLXAFOVNUYNQKUTIIPDOZECEDUBBLXETUUUDVHOZTLEJTEDYVNEILXKZOLGOZLPDVRTUKSLVWPQAAAMSIDJLSTSNEKXUVRCQYNRRZEETVNJIUXKTEEXPAAYLVRTDKWRZWEQRSEDIMQSHIJEUEYPPFYREKZCCMEZZZEKTADZLNRMRQYSAXISFOVNUILMXLPLXAFOVNUIVUKUTRPODYBNVRJQAJRLGIMRUETISEOAAEXDQYLFWSRFYJOEWIPKYASPEEVVUIVEEZHUIIRXGJOEJIMTJECISQTARVTRUYLSUSIHKUTJSUHKUTUIPXUFEIHEEIHMGEGZKZDVGOYSBNZGAFOVNVXDQXLLRXIATZPLFLUWBEJTOGXHTKINGKYLVWERLLTJRESGAIWWDGTLCPFEDGATRUUQXLUJWIQKUGVRDDGUTRMNEOKEJGOGZZSLTPXKTEEXAUXLS"
    
    repeated_sequences, distances, factor_counts = kasiski_examination(ciphertext)
    
    print("Repeated sequences and their positions:")
    for seq, positions in repeated_sequences.items():
        print(f"  {seq}: {positions}")
    
    print("\nDistances between repeated sequences:")
    print(distances)
    
    print("\nCommon factors (possible key lengths) with their counts:")
    for factor, count in factor_counts.most_common():
        print(f"  {factor}: {count}")