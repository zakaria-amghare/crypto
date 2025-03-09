from collections import Counter
import math
import os

english_letter_probabilities = [
    (' ', 0.182), ('E', 0.127), ('T', 0.091), ('A', 0.082), ('O', 0.075),
    ('I', 0.070), ('N', 0.067), ('S', 0.063), ('R', 0.060), ('H', 0.061),
    ('L', 0.040), ('D', 0.043), ('C', 0.028), ('U', 0.028), ('M', 0.024),
    ('W', 0.024), ('F', 0.022), ('G', 0.020), ('Y', 0.020), ('P', 0.019),
    ('B', 0.015), ('V', 0.0098), ('K', 0.0077), ('J', 0.0015), ('X', 0.0015),
    ('Q', 0.00095), ('Z', 0.00074)
]
french_letter_probabilities = [
    (' ', 0.175), ('E', 0.1471), ('A', 0.0764), ('S', 0.0790), ('I', 0.0752),
    ('T', 0.0724), ('N', 0.0715), ('R', 0.0669), ('U', 0.0631), ('L', 0.0546),
    ('O', 0.0579), ('D', 0.0369), ('C', 0.0326), ('M', 0.0297), ('P', 0.0252),
    ('V', 0.0183), ('Q', 0.0136), ('F', 0.0106), ('B', 0.0090), ('G', 0.0087),
    ('H', 0.0074), ('J', 0.0061), ('X', 0.0042), ('Z', 0.0032), ('Y', 0.0012),
    ('W', 0.0006), ('K', 0.0005)
]

# Frequent English digraphs
common_digraphs_en = {
    "th", "he", "in", "er", "an", "re", "on", "at", "en", "es",
    "st", "nt", "ti", "ou", "ng", "ed"
}

# Frequent French digraphs
common_digraphs_fr = {
    "es", "en", "le", "de", "nt", "ou", "et", "ai", "on", "te",
    "qu", "ch", "au", "tr", "ti"
}

common_words_en = {
    "the", "be", "to", "of", "and", "a", "in", "that", "have", "I",
    "it", "for", "not", "on", "with", "he", "as", "you", "do", "at",
    "this", "but", "his", "by", "from", "they", "we", "say", "her", "she"
}

common_words_fr = {
    "le", "être", "et", "à", "de", "un", "il", "avoir", "ne", "je",
    "son", "que", "se", "qui", "dans", "ce", "elle", "nous", "vous", "pas",
    "du", "au", "pour", "avec", "il", "sur", "mais", "plus", "tout", "comme"
}

def clear():
    input("Press enter to continue")
    os.system('cls')
    os.system('clear')

def manual_changes(sentence):
    while True:
        letter = input("Enter the letter you want to replace: ")
        if letter.lower() in sentence:
            new_letter = input("Enter the new letter: ").upper()
            sentence = sentence.replace(letter, new_letter)
            print(sentence)
        else:
            print("The letter is not in the text")
        if input("Do you want to continue? (y/n) ").lower() == 'n':
            break
    return sentence

def find_digraphs(text):
    digraphs = Counter(text[i:i+2] for i in range(len(text)-1))
    return digraphs.most_common()

def replace_letters(sorted_char_count, new_sentence, letter_probabilities):
    for i in range(len(sorted_char_count)):
        new_sentence = new_sentence.replace(sorted_char_count[i][0], "_" if letter_probabilities[i][0] == " " else letter_probabilities[i][0])
        print(new_sentence)

def char_frequency_dict(text):
    os.system('clear')
    print(text)
    char_count = Counter(text)
    sorted_char_count = sorted(char_count.items(), key=lambda item: (-item[1], item[0]))
    print(len(text), "characters")

    clear()
    
    for char, count in sorted_char_count:
        print(f"The result {char} ==> {math.floor(count * 100 / len(text))}% \n")

    clear()
    is_english = input("Is the text in English? (y/n) ").lower() == 'y'
    clear()
    letter_probabilities = english_letter_probabilities if is_english else french_letter_probabilities
    common_digraphs = common_digraphs_en if is_english else common_digraphs_fr
    word_set = common_words_en if is_english else common_words_fr
    
    new_sentence = text
    replace_letters(sorted_char_count, new_sentence, letter_probabilities)
    clear()

    new_sentence_set = new_sentence.split("_")
    for word in new_sentence_set:
        if word.lower() in word_set:
            print("We might have recognized the word:", word)
    
    for digraph in common_digraphs:  # No need for count, sets don't store frequencies
        if digraph in new_sentence:
            positions = [i for i in range(len(new_sentence)) if new_sentence.startswith(digraph, i)]
            print(f"We might have recognized the digraph: {digraph} at positions {positions}")
            for pos in positions:
                print(f"Character at position {pos}: {new_sentence[pos]}{new_sentence[pos+1]}")

    
    clear()
    if input("Can you read the text as it is? (y/n) ").lower() == 'n':
        if input("Do you want to manually replace a letter? (y/n) ").lower() == 'y':
            new_sentence_set = manual_changes(new_sentence)
        else:
            print("The text is not readable")

text = "encrypted message: f nvtu gjstu hsbtq uif dpodfqu pg b gpsnbm tztufn. Jnbhjofdiftt. Uif qjfdft boe npwft ibwf op nfbojoh pvutjef uif hbnf—uifz bsf kvtu tzncpmtnbojqvmbufe bddpsejoh up gjyfe svmft. Ijmcfsu xboufe up ftubcmjti b tjnjmbs gsbnfxpsl gpsnbuifnbujdt. If bjnfe up jefoujgz gpvoebujpobm byjpnt gspn xijdi bmm nbuifnbujdbm usvuit"
char_frequency_dict(text)
