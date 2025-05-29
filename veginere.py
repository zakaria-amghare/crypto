def vigenere_crypt(text, key):
    encrypted = ""
    key = key.upper()
    text = text.upper()
    key_length = len(key)

    for i in range(len(text)):
        c = text[i]

        if not c.isalpha():
            encrypted += c
            continue

        text_num = ord(c) - ord('A')
        key_num = ord(key[i % key_length]) - ord('A')

        encrypted_num = (text_num + key_num) % 26

        encrypted += chr(encrypted_num + ord('A'))
    return encrypted


def vigenere_decrypt(encryptedtext, key):
    decrypted = ""
    key = key.upper()
    encryptedtext = encryptedtext.upper()
    key_length = len(key)

    for i in range(len(encryptedtext)):
        c = encryptedtext[i]
        if not c.isalpha():
            decrypted += c
            continue

        encrypted_num = ord(c) - ord('A')
        key_num = ord(key[i % key_length]) - ord('A')
        decrypted_num = (encrypted_num - key_num) % 26
        decrypted += chr(decrypted_num + ord('A'))
    return decrypted


def main():
    while True:
        print("\n=== Vigenere Cipher Menu ===")
        print("1. Encrypt a message")
        print("2. Decrypt a message")
        print("3. Exit")
        choice = input("\nEnter your choice (1-3): ")

        if choice == '1':
            message = input("Enter the message to encrypt: ")
            key = input("Enter the key: ")
            encrypted = vigenere_crypt(message, key)
            print(f"\nEncrypted message: {encrypted}")

        elif choice == '2':
            message = input("Enter the message to decrypt: ")
            key = input("Enter the key: ")
            decrypted = vigenere_decrypt(message, key)
            print(f"\nDecrypted message: {decrypted}")

        elif choice == '3':
            print("Exiting program. Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()