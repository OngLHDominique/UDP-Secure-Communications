# Setup.py to be run as the first file.
# Refer to README.txt for the full instructions.

import hashlib
from Crypto.Util.number import getPrime
import os

# Setting common password for both users
pwd = "SecretPwd2026"

# Hash the password using SHA-1
# Encode the password to bytes before hashing
hashedPwd = hashlib.sha1(pwd.encode('utf-8')).hexdigest()

# Generate Diffie-Hellman parameters (p, g)
print("[+] Generating Diffie-Hellman parameters (this might take some time) ...")
p = getPrime(512)
g = 2

# Check for existing directory for Alice
if not os.path.exists("Alice"):
    os.makedirs("Alice")

# Save (p, g, H(pwd)) to a text file in Alice's directory
filePath = "Alice/host_setup.txt"
with open(filePath, "w") as f:
    f.write(f"{p}\n")
    f.write(f"{g}\n")
    f.write(f"{hashedPwd}\n")

print(f"[+] Setup complete! Parameters saved to {filePath}")

# Owner: Ong Lee Heung, Dominique