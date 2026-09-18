# Client.py to be run after Host.py.
# Refer to README.txt for the full instructions.

import socket
import sys
import hashlib
import random

def rc4(key_string, data_bytes):
    # RC4 encryption/decryption stream cipher
    key = key_string.encode('utf-8')

    # Implements Key-Scheduling Algorithm (KSA)
    S = list(range(256))
    j = 0
    
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # Implements Pseudo-Random Generation Algorithm (PRGA)
    res = []
    i = j = 0
    for byte in data_bytes:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K_stream = S[(S[i] + S[j]) % 256]
        res.append(byte ^ K_stream)

    return bytes(res)

def main():
    # Assign IP address and Port Number to establish connection
    ip = "127.0.0.1"
    port = int(4444)

    # Create socket for host
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    
    # -- Handshake phase
    # Prompt for the password and hash it
    pwd = input("Enter password : ")
    hashedPwd = hashlib.sha1(pwd.encode('utf-8')).hexdigest()

    # Send Step 1 message
    print("[*] Initiating handshake ...")
    s.sendto("Bob".encode('utf-8'), (ip, port))

    # Receive Step 2 response
    data, address = s.recvfrom(4096)

    # Decrypt payload using RC4
    try:
        decryptedPayload = rc4(hashedPwd, data).decode('utf-8')
        pStr, gStr, hostAStr = decryptedPayload.split(',')

        p = int(pStr)
        g = int(gStr)
        hostA = int(hostAStr) # This is to calculate g^a mod p

        print(f"[+] Handshake Step 2 successful. Received p, g, and A from Host.")

        # Generate b, derive session key K, and send g^b mod p
        # Generate random b and computer g^b mod p
        b = random.randint(2, p-2)
        clientB = pow(g, b, p)

        # -- Step 3, Derive shared session key K = H(g^(ab) mod p)
        sharedSecret = pow(hostA, b, p)
        K = hashlib.sha1(str(sharedSecret).encode('utf-8')).hexdigest()
        print("[+] Session Key K successfully established.")

        # Encrypt B using the password hash and send it to Host
        payloadStp3 = str(clientB).encode('utf-8')
        ciphertextStp3 = rc4(hashedPwd, payloadStp3)
        s.sendto(ciphertextStp3, (ip, port))
        print("[*] Step 3: Sent encrypted B (g^b mod p) to Host.")

        # -- Step 4, Reception, Receive nonce NA from Host
        data, address = s.recvfrom(4096)

        # Checks if Host-side aborted the handshake (e.g., failed decryption)
        if data == b"Login Failed":
            print("[-] Host aborted handshake (likely wrong password). Terminating ...")
            s.close()
            print("[-] Service successfully terminated.")
            sys.exit()

        # Decrypt using the NEW session key K (not hashedPwd)
        decryptedNA = rc4(K, data).decode('utf-8')
        NA = int (decryptedNA)
        print(f"[+] Step 4 successful. Received Nonce NA: {NA}")

        # -- Step 5, Generate nonce NB and send E(K, NA + 1, NB)
        NB = random.randint(1000, 9999)
        payloadStp5 = f"{NA + 1},{NB}".encode('utf-8')

        # Encrypt using session key K
        ciphertextStp5 = rc4(K, payloadStp5)
        s.sendto(ciphertextStp5, (ip, port))
        print(f"[*] Step 5: Sent E(K, NA + 1, NB) to Host. (NB = {NB})")

        # -- Step 6, Reception, Verify NB + 1 from Host
        data, address = s.recvfrom(4096)

        decryptedResponse = rc4(K, data).decode('utf-8')

        # Check if Host rejected the login or if math is incorrect
        if decryptedResponse == "Login Failed" or int(decryptedResponse) != NB + 1:
            print("[-] Handshake Failed! Verification of NB + 1 was incorrect or login failed.")
            print("[-] Login failed!")
            print("[-] Incorrect password or corrupted data. Terminating ...")
            s.close()
            print("[-] Service successfully terminated.")
            sys.exit()
        else:
            print(f"[+] Step 6 successful. Received valid NB + 1 ({decryptedResponse}).")
            print("[+] --- HANDSHAKE COMPLETE, SECURE CHANNEL ESTABLISHED ---")

    except Exception as e:
        print("[-] Login failed!")
        print("[-] Incorrect password or corrupted data. Terminating ...")
        s.sendto(b"Login Failed", (ip, port)) # Terminates connection with the Host
        s.close()
        print("[-] Service successfully terminated.")
        sys.exit()
    
    # -- Chat phase
    print("[+] Service established.")
    print("[*] Type 'exit' to terminate service.")

    # Send data through UDP protocol
    while True:
        print("\r")
        print('[+] Client is listening ...')
        print("\r")

        # -- 1. Message to host-side
        sendData = input("To Host => ")

        # Step 1a, Compute hash = H(K||M||K)
        msgHash = hashlib.sha1((K + sendData + K).encode('utf-8')).hexdigest()

        # Step 1b, Compute C = E(K, M||hash)
        payloadToSend = f"{sendData}||{msgHash}".encode('utf-8')
        cipherText = rc4(K, payloadToSend)

        # Step 1c, Send C to Host
        s.sendto(cipherText, (ip, port))

        # Checking for termination of service from client-side
        if sendData.lower() == 'exit':
            print("\r")
            print("[-] Client initiated termination of service ...")
            print("[-] Service is terminating ...")
            break

        # -- 2. Receiving message from host-side
        data, address = s.recvfrom(4096)

        try:
            # Step 2a, Decrypt D(K, C) to obtain M||hash
            decryptedData = rc4(K, data).decode('utf-8')

            # Use rsplit from the right to cleanly separate the characters in the SHA1 hash
            hostMsg, receivedHash = decryptedData.rsplit('||', 1)

            # Step 2b, Recompute hash' = H(K||M||K)
            expectedHash  = hashlib.sha1((K + hostMsg + K).encode('utf-8')).hexdigest()

            # Step 2c, Check if hash == hash'
            if receivedHash == expectedHash:
                print("From Host=>", hostMsg)
            else:
                print("[-] Error: Message integrity check failed! (Hash mismatch)")
                continue
        except Exception as e:
            print("[-] Error: Failed to decrypt or parse incoming message.")
            continue

        # Checking for termination of service from host-side
        if hostMsg.lower() == 'exit':
            print("\r")
            print("[+] Host initiated termination of service ...")
            print("[+] Service is terminating ...")
            break

    # Close socket
    s.close()
    print("\r")
    print("[-] Service successfully terminated.")

if __name__ == "__main__":
    main()

# Owner: Ong Lee Heung, Dominique