### Rapport des Fichiers Individuels

---

#### **1. vigenere.py**
- **But** : Implémente le chiffre de Vigenère pour le chiffrement/déchiffrement de texte.
- **Fonctionnalités** :
  - Classe `VigenereCipher` avec méthodes `chiffrer_vigenere` et `dechiffrer_vigenere`.
  - Interface utilisateur interactive pour saisir le texte, la clé, et afficher les résultats.
  - Support des caractères non alphabétiques (conservés tels quels).
  - Conversion Base64 pour le texte chiffré.
- **Algorithme** : Utilise une clé répétée pour décaler les lettres selon leurs positions.
- **Technique** : Gère les majuscules/minuscules et ignore les caractères spéciaux.

---

#### **2. signature.py**
- **But** : Génère des signatures numériques via RSA et vérifie leur authenticité.
- **Fonctionnalités** :
  - Génération de clés RSA avec test de primalité Miller-Rabin.
  - Fonctions `sign_message` (signature) et `verify_signature` (vérification).
  - Hachage SHA-256 des messages.
  - Interface de démonstration avec tests de validité.
- **Algorithme** : RSA pour la signature, SHA-256 pour le hachage.
- **Technique** : Utilise l’algorithme d’Euclide étendu pour calculer l’inverse modulaire.

---

#### **3. RSA.py**
- **But** : Chiffrement/déchiffrement asymétrique avec RSA.
- **Fonctionnalités** :
  - Génération de clés (publique/privée) de 512 à 1024 bits.
  - Chiffrement de messages avec gestion de la taille maximale.
  - Sauvegarde/chargement des clés au format JSON.
  - Interface utilisateur complète avec options de chiffrement, déchiffrement, et gestion de clés.
- **Algorithme** : RSA standard avec padding manuel.
- **Technique** : Utilise `pow(e, -1, phi)` pour calculer l’inverse modulaire.

---

#### **4. RC4.py**
- **But** : Chiffrement/déchiffrement symétrique via l’algorithme RC4.
- **Fonctionnalités** :
  - Génération de flux de clés (keystream) via KSA et PRGA.
  - Analyse statistique du keystream (fréquence des bytes).
  - Interface pour générer des clés aléatoires (8 à 256 bytes).
- **Algorithme** : RC4 avec XOR entre le texte et le keystream.
- **Technique** : Gère les clés en hexadécimal, Base64, ou texte.

---

#### **5. AES.py**
- **But** : Chiffrement/déchiffrement via AES-128.
- **Fonctionnalités** :
  - Implémentation complète des étapes AES : SubBytes, ShiftRows, MixColumns, AddRoundKey.
  - Padding PKCS7 pour les données.
  - Interface utilisateur avec génération de clés aléatoires (16 bytes).
- **Algorithme** : AES-128 avec tours répétés et tables prédéfinies (S-box).
- **Technique** : Utilise des opérations dans le corps de Galois (multiplications).

---

#### **6. dechiffrement_cesar.py**
- **But** : Chiffre de César avec analyse fréquentielle pour casser le code.
- **Fonctionnalités** :
  - Chiffrement/déchiffrement avec clé numérique.
  - Analyse basée sur les fréquences des lettres en français.
  - Affichage des tables de substitution.
  - Démonstration pédagogique.
- **Algorithme** : César classique avec décalage modulaire.
- **Technique** : Pondération des résultats via les statistiques linguistiques.

---

#### **7. DES.py**
- **But** : Chiffrement/déchiffrement symétrique via DES.
- **Fonctionnalités** :
  - Implémentation des permutations (IP/FP), S-boxes, et tours de Feistel.
  - Génération de 16 sous-clés à partir d’une clé principale.
  - Padding PKCS7 et gestion des blocs de 8 bytes.
- **Algorithme** : DES standard avec 16 tours.
- **Technique** : Utilise des tables de permutation prédéfinies et des substitutions non linéaires.

---

#### **8. implimentaion.py**
- **But** : Intégration de tous les algorithmes dans un menu unifié.
- **Fonctionnalités** :
  - Appel des fonctions `main` de chaque fichier (AES, DES, RSA, etc.).
  - Menu interactif pour choisir entre 9 méthodes de chiffrement.
  - Gestion centralisée des options utilisateur.
- **Technique** : Agit comme un wrapper pour exécuter les scripts individuels.

---

### **Conclusion**

Ce projet regroupe des implémentations variées de méthodes cryptographiques classiques et modernes. Chaque algorithme a ses forces et cas d’usage :

- **Symétrique** (AES, DES, RC4) : Rapide et adapté au chiffrement de gros volumes de données. AES est recommandé pour sa sécurité, tandis que DES et RC4 sont présentés à titre éducatif.
- **Asymétrique** (RSA, ElGamal) : Idéal pour l’échange de clés et les signatures numériques, bien que plus lent.
- **Chiffres historiques** (César, Vigenère) : Utiles pour comprendre les bases, mais vulnérables aux attaques statistiques.
- **Outils d’analyse** (Kasiski, analyse fréquentielle) : Permettent de casser des chiffrements faibles.

Les interfaces utilisateur rendent ces outils accessibles pour des démonstrations pédagogiques, bien que certaines implémentations (comme RSA avec de petites clés) ne soient pas adaptées à un usage réel. Ce projet illustre bien la diversité des techniques cryptographiques et leurs applications pratiques.
9. kasiskiAndSomeFunction.py

But : Outils de cryptanalyse pour casser des chiffrements polyalphabétiques (ex: Vigenère).

Fonctionnalités :

Test de Kasiski pour estimer la longueur de clé via les séquences répétées.

Calcul de l'indice de coïncidence (IC) pour valider les hypothèses de longueur de clé.

Analyse fréquentielle comparée (français/anglais) avec calcul du chi-carré.

Interface interactive pour tester différentes méthodes.

Algorithmes :

Kasiski : Identification des distances entre séquences répétées et factorisation.

IC : Mesure de similarité linguistique par groupe de lettres.

Technique : Combinaison de méthodes statistiques et algébriques pour une cryptanalyse complète.

10. ElGamal.py

But : Implémentation du chiffrement asymétrique ElGamal basé sur le problème du logarithme discret.

Fonctionnalités :

Génération de clés avec des nombres premiers de 2048 bits et recherche de racines primitives.

Chiffrement/déchiffrement de messages (texte ou entier) avec gestion des grands nombres.

Démonstration interactive et tests personnalisés.

Algorithmes :

Exponentiation modulaire pour le chiffrement (c1 = g^k mod p, c2 = m * y^k mod p).

Petit théorème de Fermat pour calculer l'inverse modulaire lors du déchiffrement.

Technique : Utilise des opérations modulaires sécurisées et des nombres premiers robustes.

Conclusion (Mise à Jour)

Ce projet étend désormais sa couverture à des méthodes avancées de cryptanalyse et de cryptographie asymétrique :

Cryptanalyse (Kasiski) : Les outils de kasiskiAndSomeFunction.py complètent les chiffrements historiques (César, Vigenère) en fournissant des méthodes pour les casser. L'analyse statistique (IC) et algébrique (Kasiski) permet de comprendre les vulnérabilités des systèmes classiques.

ElGamal : Cet algorithme asymétrique enrichit la palette des méthodes modernes, offrant une alternative à RSA pour l'échange de clés et le chiffrement. Son implémentation avec des clés de 2048 bits souligne l'importance des grands nombres premiers en cryptographie.

Synthèse des Contributions :

Diversité : Le projet couvre désormais des techniques allant des chiffrements historiques (César) aux protocoles asymétriques modernes (RSA, ElGamal), en passant par des outils pédagogiques de cryptanalyse.

Pédagogie : Les interfaces interactives et les démonstrations étape par étape (ex: étapes de chiffrement ElGamal) rendent les concepts accessibles.

Sécurité Pratique : Bien que certaines implémentations (ex: DES, RC4) soient présentées à titre éducatif, d'autres (AES, ElGamal) illustrent les standards actuels.

Ce travail sert à la fois de référence technique et de laboratoire d'expérimentation pour explorer les forces et limites des différentes approches cryptographiques.