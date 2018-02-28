# -*- coding: utf-8 -*-
"""
Created on Mon Jun 29 14:36:31 2015

@author: locksmith
"""

import pyelliptic
import pyelliptic.arithmetic
#from pyelliptic.openssl import OpenSSL
#from charm.core.math.elliptic_curve import elliptic_curve,ec_element,ZR,G,init,random,order,getGenerator,bitsize,serialize,deserialize,hashEC,encode,decode,getXY
#import charm.core.math.elliptic_curve
import charm.toolbox.ecgroup
import charm.schemes.pksig.pksig_ecdsa
import charm.schemes.pksig.pksig_dsa
import charm.toolbox.eccurve
from charm.core.math.integer import integer
import OpenSSL
import hashlib
import socket
import pprint
import time
import os.path
#from charm.toolbox.ecgroup import ECGroup,ZR,G
#from charm.toolbox.PKSig import PKSig


def create_self_signed_cert():
    """
    If crt and key don't exist in cert_dir, create a new
    self-signed cert and keypair and write them into that directory.
    """
    CERT_FILE = "locationService.crt"
    KEY_FILE = "locationService.key"

    # If the files are not here, then just create them.    
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
            
        # create a key pair
        pkey = OpenSSL.crypto.PKey()
        pkey.generate_key(OpenSSL.crypto.TYPE_RSA, 3072)
        
        # create a self-signed cert
        cert = OpenSSL.crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "Delaware"
        cert.get_subject().L = "Newark"
        cert.get_subject().O = "PristineTechLocker"
        cert.get_subject().OU = "PristineTechLocker"
        cert.get_subject().CN = socket.gethostname()
        cert.set_serial_number(888)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10*365*24*60*60) # 10 years of validity in seconds.
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(pkey)
        cert.sign(pkey, 'sha256')
        #print(cert)

        with open(CERT_FILE, "wt") as cert_file, open(KEY_FILE, "wt") as key_file, open(CERT_FILE + ".txt", "wt") as cert_file_txt:
            cert_file.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert).decode())
            key_file.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey).decode())
            cert_file_txt.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_TEXT, cert).decode())
            
    # If the files exist, then retrieve their data into the certificate and Pkey.
    else:
        with open(CERT_FILE, "rt") as cert_file, open(KEY_FILE, "rt") as key_file:  
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_file.read())
            pkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key_file.read())
        
    return cert, pkey
        
        
        
alice = pyelliptic.ECC() # default curve: sect283r1
bob = pyelliptic.ECC(curve='secp256k1')
ciphertext = alice.encrypt("Hello Bob", bob.get_pubkey())

print(bob.decrypt(ciphertext))
signature = bob.sign("Hello Alice")
print("Signature: ", signature)

# alice's job :
print(pyelliptic.ECC(pubkey=bob.get_pubkey()).verify(signature, "Hello Alice"))
    
# ERROR !!!
try:
    key = alice.get_ecdh_key(bob.get_pubkey())
except:
    print("For ECDH key agreement, the keys must be defined on the same curve !")
              
alice = pyelliptic.ECC(curve='secp256k1')
print(alice.get_ecdh_key(bob.get_pubkey()))
print(bob.get_ecdh_key(alice.get_pubkey()))
print("\n\nPublic keys:")
print("Bob: ", bob.get_pubkey())
print("Alice: ", alice.get_pubkey())
print("Private keys:")
print("Bob: ", bob.get_privkey())
print("Alice: ", alice.get_privkey())

# Let's try some arithmetic here.

# Alice and Bob have public keys, which are points in elliptic curves. Let's add them.

#alicexbob = pyelliptic.arithmetic.add(alice.get_pubkey(), bob.get_pubkey())
"""
>>> from charm.toolbox.eccurve import prime192v2
>>> group = ECGroup(prime192v2)
>>> ecdsa = ECDSA(group)
>>> (public_key, secret_key) = ecdsa.keygen(0)
>>> msg = "hello world! this is a test message."
>>> signature = ecdsa.sign(public_key, secret_key, msg)
>>> ecdsa.verify(public_key, signature, msg)
True
"""
group = charm.toolbox.ecgroup.ECGroup(charm.toolbox.eccurve.secp256k1)
# Alice
ecdsa_alice = charm.schemes.pksig.pksig_ecdsa.ECDSA(group)
alice_public_key, alice_secret_key = ecdsa_alice.keygen(0)
print("Alice ECDSA public key: ", alice_public_key)
print("Alice ECDSA secret key: ", alice_secret_key)

# Bob
ecdsa_bob = charm.schemes.pksig.pksig_ecdsa.ECDSA(group)
bob_public_key, bob_secret_key = ecdsa_bob.keygen(0)
print("Bob ECDSA public key: ", bob_public_key)
print("Bob ECDSA secret key: ", bob_secret_key)

# Add?
print("Alice y point: ", alice_public_key['y'])
print("Bob y point: ", bob_public_key['y'])
# Note that Charm overloads operators such that operations under Zr (integer) fields are written the same way as those under EC groups.
# I.e., g**x is written as is under Zr or G, but under G, it really means x*G. Likewise, a*b is written the same, but means a + b under EC groups.
# Therefore, the multiplication below is an "add" for EC points.
print("Adding Alice and Bob public keys: ", alice_public_key['y'] * bob_public_key['y'])

# Now the power here is a multiplication for EC group. Note the order; the base must come first, obviously, but it becomes the right-hand-side of the
# EC multiplication: alice_secret_key * bob_public_key
print("Multiplying Alice secret and Bob public key: ", bob_public_key['y'] ** alice_secret_key)

# Now let's see some public signature (DSA).

p = integer(156053402631691285300957066846581395905893621007563090607988086498527791650834395958624527746916581251903190331297268907675919283232442999706619659475326192111220545726433895802392432934926242553363253333261282122117343404703514696108330984423475697798156574052962658373571332699002716083130212467463571362679)
q = integer(78026701315845642650478533423290697952946810503781545303994043249263895825417197979312263873458290625951595165648634453837959641616221499853309829737663096055610272863216947901196216467463121276681626666630641061058671702351757348054165492211737848899078287026481329186785666349501358041565106233731785681339)    
dsa = charm.schemes.pksig.pksig_dsa.DSA(p, q)
(public_key, secret_key) = dsa.keygen(1024)
print("DSA keys: ", public_key, secret_key)
msg = "hello world test message!!!".encode()
#signature = dsa.sign(public_key, secret_key, msg)
#print("Signature: ", signature)
#print("Verification: ", dsa.verify(public_key, signature, msg))

#Create X.509 self-signed certificate and secret key, or read them from file if already exist.
cert, opensslkey = create_self_signed_cert()
print("Certificate X.509: ", OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
print("Private key (PKey): ", OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, opensslkey))
#opensslobject = OpenSSL.crypto.PKey()
#opensslobject.generate_key(OpenSSL.crypto.TYPE_DSA, 256)
opensslsignature = OpenSSL.crypto.sign(opensslkey, "blablabla", 'sha256')
print("Signature: ", opensslsignature)
try:
    print("Verify? ", OpenSSL.crypto.verify(cert, opensslsignature, "blablabla", 'sha256'))
except:
    print("Bad signature!")
    
# Validity of the certificate.
print("Has certificate expired? ", cert.has_expired())



