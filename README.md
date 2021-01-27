# sp_project
MitM attack on Curve25519 DH

# Description
    - Context:
        - Server and Client generate an ephemeral key pair on Curve25519;
        - Server sends its eph public key authenticated (signed) with the RSA key and a nounce;
        - Client verifies servers eph public key authenticity and sends back its public key and a nounce;
        - Server and Client generate the shared secret (DH using peer's public key) and authenticate the exchange
          by computing a MAC over the peer's nounce concateneted with a pre-shared secret (password);
        - After the key exchange was authenticated, they can start communicating via messages encrpyted with the computed shared secret;
    - Tried to find out the password from the mac shared by the server (communicating with the server: shared_secret and nounce known) using `hashcat`;
      If it were a weak password (in the 5 characters space it would have been cracked in matter of minutes); however it wasn't the case;
    - Attack:
        1. Break server authentication for the client side:
            - While searching for attacks on PKCS1_15 signatures, I started the factorization of the modulus using this site (https://www.alpertron.com.ar/ECMC.HTM)
              which under 10 minutes has been successful;
            -> Computed the server private key; Now can impersonate as server for the client side;
        2. Break/Bypass key exchange authentication:
            - As password wasn't easy crackabale, I shifted the focus on the shared secret (I can authenticate the exchange dispatching the messages betwee Server and Client,
              however to be able to communicate furhter with the server I must have the same shared secret);
            - Looking at the validation for the public key, noticed that values 0 and 1 where not accepted; Trying these value in doing a key exchange
              resulted in the same shared secret (no matter what private key was used) - zero keys;
            - Investigating further this property (public keys on Curve25519 giving the same shared secret), I came upon this site (https://cr.yp.to/ecdh.html)
              which contain additional values for the public key on Curve25519 having the same property;
    - With the carefully chosen public key on Curve25519 (authenticated with the cracked RSA private key), I authenticated to the client and server.
    
# Run
    ./exploit.py

