# Host.py to be run after Setup.py have generating the keys.
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

    # Create a UDP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Bind the socket to the port
    hostAddress = (ip, port)
    s.bind(hostAddress)
    print("[+] Service established.")

    # -- Handshake phase
    # Read setup parameters
    try:
        with open("host_setup.txt", "r") as f:
            p = int(f.readline().strip())
            g = int(f.readline().strip())
            hashedPwd = f.readline().strip()
    except FileNotFoundError:
        print("[-] Setup file not found. Run Setup.py first.")
        sys.exit()

    print("[*] Waiting for connection request ...")

    # Wait for the message, 'Bob'
    data, address = s.recvfrom(4096)
    clientMsg = data.decode('utf-8')

    if clientMsg == "Bob":
        print(f"[+] Connection request 'Bob' received from {address}")

        # Generate random 'a' and computer g^a mod p
        a = random.randint(2, p-2)
        A = pow(g, a, p)
    
        # Construct payload: p, g, g^a mod p
        payload = f"{p},{g},{A}".encode('utf-8')

        # Encrypt with RC4 using hashed password as key
        ciphertext = rc4(hashedPwd, payload)

        # Send Step 2 message
        s.sendto(ciphertext, address)
        print("[*] Step 2: Sent encrypted parameters to Client.")

        # -- Step 3, Reception, Receive g^b mod p from Client
        data, address = s.recvfrom(4096)

        # Checks if Client-side aborted the handshake (e.g., wrong password input)
        if data == b"Login Failed":
            print("[-] Client aborted handshake (likely wrong password). Terminating ...")
            s.close()
            sys.exit()

        try:
            decryptedB = rc4(hashedPwd, data).decode('utf-8')
            clientB = int(decryptedB)
            print(f"[+] Step 3 successful. Received B (g^b mod p) from Client.")
        except Exception as e:
            print("[-] Failed to decrypt Client B. Terminating ...")

            try:
                s.sendto(b"Login Failed", address)
            except Exception as e:
                pass

            s.close()
            print("[-] Service successfully terminated.")
            sys.exit()

        # Derived shared session key K = H(g^(ab) mod p)
        sharedSecret = pow(clientB, a, p)
        K = hashlib.sha1(str(sharedSecret).encode('utf-8')).hexdigest()
        print("[+] Shared Key K successfully established.")

        # -- Step 4, Generate nonce NA and send E(K, NA)
        NA = random.randint(1000, 9999)
        payloadStp4 = str(NA).encode('utf-8')

        # Encrypt using the new session key K (not hashedPwd)
        ciphertextStp4 = rc4(K, payloadStp4)
        s.sendto(ciphertextStp4, address)
        print(f"[+] Step 4: Sent encrypted Nonce NA ({NA}) to Client.")
        
        # -- Step 5, Reception, Receive E(K, NA + 1, NB) from Client
        data, address = s.recvfrom(4096)

        # Checks if Client-side aborted the handshake
        if data == b"Login Failed":
            print("[-] Client aborted handshake (likely wrong password). Terminating ...")
            s.close()
            print("[-] Service successfully terminated.")
            sys.exit()

        try:
            decryptedPayload = rc4(K, data).decode('utf-8')
            naPlus1Str, nbStr = decryptedPayload.split(',')
            receivedNAPlus1 = int(naPlus1Str)
            NB = int(nbStr)
            print(f"[+] Step 5 successful. Received NA + 1 ({receivedNAPlus1}) and NB ({NB}).")
        except Exception as e:
            print("[-] Failed to decrypt or parse Step 5 payload. Terminating ...")

            try:
                s.sendto(b"Login Failed", address)
            except Exception as e:
                pass

            s.close()
            sys.exit()

        # -- Step 6, Verify NA + 1 and respond
        if receivedNAPlus1 == NA + 1:
            print("[+] Nonce NA successfully verified!")

            # Send E(K, NB + 1)
            payloadStp6 = str(NB + 1).encode('utf-8')
            ciphertextStp6 = rc4(K, payloadStp6)
            s.sendto(ciphertextStp6, address)
            print(f"[*] Step 6: Sent E(K, NB + 1) to Client.")
            print("[+] --- HANDSHAKE COMPLETE, SECURE CHANNEL ESTABLISHED ---")
        else:
            print("[-] Nonce verified failed! Sending 'Login Failed' and terminating.")

            # Send encrypted "Login Failed" message so client can cleanly decrypt and read it
            errorMsg = rc4(K, "Login Failed".encode('utf-8'))
            s.sendto(errorMsg, address)
            print("[-] Service terminating ...")
            s.close()
            print("[-] Service successfully terminated.")
            sys.exit()          

    else:
        print("[-] Unrecognized connection request. Terminating ...")
        s.close()
        print("[-] Service successfully terminated.")
        sys.exit()
        
    # -- Chat phase
    print("[*] Type 'exit' to terminate service.")

    while True:
        print("\r")
        print("[+] Host is listening ...")
        print("\r")

        # -- 1. Receiving message from Client
        data, address = s.recvfrom(4096)

        try:
            # Step 2a, Decrypt D(K, C) to obtain M || hash
            decryptedData = rc4(K, data).decode('utf-8')

            # Use rsplit from the right to cleanly separate the characters in the SHA1 hash
            clientMsg, receivedHash = decryptedData.rsplit('||', 1)

            # Step 2b, Recompute hash'  = H(K||M||K)
            expectedHash = hashlib.sha1((K + clientMsg + K).encode('utf-8')).hexdigest()

            # Step 2c, Check if hash == hash'
            if receivedHash == expectedHash:
                print("From Client=> ", clientMsg)
            else:
                print("[-] Error: Message integrity check failed! (Hash mismatch)")
                continue
        except Exception as e:
            print("[-] Error: Failed to decrypt or parse incoming message.")
            continue

        # Check input for termination of service from client-side
        if clientMsg.lower() == 'exit':
            print("\r")
            print("[-] Client initiated termination of service ...")
            print("[-] Service is terminating ...")
            break
        
        # -- 2. Sending message to client-side
        sendData = input("To Client=> ")

        # Step 1a, Compute hash = H(K||M||K)
        msgHash = hashlib.sha1((K + sendData + K).encode('utf-8')).hexdigest()

        # Step 1b, Compute C = E(K, M||hash)
        payloadToSend = f"{sendData}||{msgHash}".encode('utf-8')
        cipherText = rc4(K, payloadToSend)

        # Step 1c, Send C to Client
        s.sendto(cipherText, address)

        # Check input for termination of service from host-side
        if sendData.lower() == 'exit':
            print("\r")
            print("[-] Host initiated termination of service ...")
            print("[-] Service is terminating ...")
            break

    # Close socket
    s.close()
    print("\r")
    print("[-] Service successfully terminated.")
 
if __name__ == "__main__":
    main()

# Owner: Ong Lee Heung, Dominique