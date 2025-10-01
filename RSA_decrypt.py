from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from pathlib import Path
from Crypto.Random import get_random_bytes

def decrypt_with_rsa():
    keyfile = r"H:\Python\RSA101\key.pem"   #the Path of the key 
    encfile = r"H:\Python\RSA101\cipher"   # The path of encoding file 
    outfile = r"H:\Python\RSA101\output.txt"     

    key_data = Path(keyfile).read_bytes()
    key = RSA.import_key(key_data)

    ciphertext = Path(encfile).read_bytes()

    try:
        cipher = PKCS1_OAEP.new(key)
        plaintext = cipher.decrypt(ciphertext)
        print("[+] Decrypted using OAEP")
    except Exception:
        cipher = PKCS1_v1_5.new(key)
        sentinel = get_random_bytes(16)
        plaintext = cipher.decrypt(ciphertext, sentinel)
        print("[+] Decrypted using PKCS1_v1_5")

    Path(outfile).write_bytes(plaintext)
    print(f"[+] Decrypted text written to {outfile}")

if __name__ == "__main__":
    decrypt_with_rsa()
