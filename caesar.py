
shift = 5
text = "Дальше будет хуже:)"


def cipher_encrypt(plain_text:str, key):
    encrypted = ""
    for c in plain_text:

        if c.isupper():
            c_index = ord(c) - ord('А')

            c_shifted = (c_index + key) % 33 + ord('А')
            c_new = chr(c_shifted)
            encrypted+=c_new
        elif c.islower():

            c_index = ord(c) - ord('а')
            c_shifted = (c_index + key) % 33 + ord('а')
            c_new = chr(c_shifted)
            encrypted += c_new

        elif c.isdigit():

            c_new = (int(c)+key)% 10
            encrypted += str(c_new)
        else:

            encrypted += c

    return encrypted


def cipher_decrypt(chiphertext, key):
    decrypted = ""
    for c in chiphertext:
        if c.isupper():

            c_index = ord(c) - ord('А')

            c_og_pos = (c_index - key) % 33 + ord('А')
            c_og = chr(c_og_pos)
            decrypted += c_og
        elif c.islower():

            c_index = ord(c) - ord('а')

            c_og_pos = (c_index - key) % 33 + ord('а')
            c_og = chr(c_og_pos)

            decrypted += c_og

        elif c.isdigit():

            c_og = (int(c) - key)% 10
            decrypted += str(c_og)

        else:
            decrypted += c

    return decrypted

print(cipher_encrypt(text,shift))
print(cipher_decrypt(cipher_encrypt(text,shift), shift))



