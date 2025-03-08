from collections import Counter
import math
english_letter_probabilities = [
    ('E', 0.127), ('T', 0.091), ('A', 0.082), ('O', 0.075), ('I', 0.070),
    ('N', 0.067), ('S', 0.063), ('R', 0.060), ('H', 0.061), ('L', 0.040),
    ('D', 0.043), ('C', 0.028), ('U', 0.028), ('M', 0.024), ('W', 0.024),
    ('F', 0.022), ('G', 0.020), ('Y', 0.020), ('P', 0.019), ('B', 0.015),
    ('V', 0.0098), ('K', 0.0077), ('J', 0.0015), ('X', 0.0015), ('Q', 0.00095),
    ('Z', 0.00074)
]
french_letter_probabilities = [
    ('E', 0.1471), ('A', 0.0764), ('S', 0.0790), ('I', 0.0752), ('T', 0.0724),
    ('N', 0.0715), ('R', 0.0669), ('U', 0.0631), ('L', 0.0546), ('O', 0.0579),
    ('D', 0.0369), ('C', 0.0326), ('M', 0.0297), ('P', 0.0252), ('V', 0.0183),
    ('Q', 0.0136), ('F', 0.0106), ('B', 0.0090), ('G', 0.0087), ('H', 0.0074),
    ('J', 0.0061), ('X', 0.0042), ('Z', 0.0032), ('Y', 0.0012), ('W', 0.0006),
    ('K', 0.0005)
]

def char_frequency_dict(text):


    char_count = Counter(text)
    sorted_char_count = sorted(char_count.items(), key=lambda item: (-item[1], item[0]))

    print(english_letter_probabilities)
    print(len(text))
    for i in range(len(sorted_char_count)):
        print("the result ",sorted_char_count[i][0],"==>",math.floor(sorted_char_count[i][1]*100/len(text)),"% \n")

    is_english = input("Is the text in English? (y/n) ")
    if is_english.lower() == 'y':
         is_english = True
    else:
         is_english = False

    if is_english:
        letter_probabilities = english_letter_probabilities
    else:    
        letter_probabilities = french_letter_probabilities
    new_sentence = text
    for i in range(len(sorted_char_count)):
        new_sentence = new_sentence.replace(sorted_char_count[i][0], letter_probabilities[i][0])
        print(new_sentence)

    return sorted_char_count


text = "hello world"
char_frequency_dict(text)
