# -*- coding: utf-8 -*-
"""
Created on Tue Sep 15 16:28:40 2015

@author: locksmith
"""
#from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction
#from charm.core.math.pairing import hashPair as sha1
from charm.schemes.abenc.dabe_aw11 import Dabe
#from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
from charm.toolbox.pairinggroup import PairingGroup
from charm.adapters.dabenc_adapt_hybrid import HybridABEncMA
import json
import jsonhelper
import charm.core.math.pairing
import types

from charm.core.engine.util import objectToBytes, bytesToObject


debug = True

def main():
    groupObj = PairingGroup('SS512')
    dabe = Dabe(groupObj)
    # Waste one random instance of the PRG sequence.
    #print(groupObj.random())

    hyb_abema = HybridABEncMA(dabe, groupObj)

    #Setup global parameters for all new authorities
    gp = hyb_abema.setup()

    #Instantiate a few authorities
    #Attribute names must be globally unique.  HybridABEncMA
    #Two authorities may not issue keys for the same attribute.
    #Otherwise, the decryption algorithm will not know which private key to use
    jhu_attributes = ['jhu.professor', 'jhu.staff', 'jhu.student']
    jhmi_attributes = ['jhmi.doctor', 'jhmi.nurse', 'jhmi.staff', 'jhmi.researcher']
    (jhuSK, jhuPK) = hyb_abema.authsetup(gp, jhu_attributes)
    (jhmiSK, jhmiPK) = hyb_abema.authsetup(gp, jhmi_attributes)
    allAuthPK = {}; allAuthPK.update(jhuPK); allAuthPK.update(jhmiPK)
    
    # Generate new keys with same parameters, such that we demonstrate whether ciphertexts encrypted with these new keys
    # cannot be decrypted with old user's keys.
    (jhuSKnew, jhuPKnew) = hyb_abema.authsetup(gp, jhu_attributes)
    (jhmiSKnew, jhmiPKnew) = hyb_abema.authsetup(gp, jhmi_attributes)
    allAuthPKnew = {}; allAuthPKnew.update(jhuPKnew); allAuthPKnew.update(jhmiPKnew)


    #Setup a user with a few keys
    bobs_gid = "20110615 bob@gmail.com cryptokey"
    K = {}
    Ksame = {} # A key to allow us to demonstrate that the generation creates the same keys a second time; keygen is deterministic.
    print("JhuSK: ", jhuSK)
    print("jhmiSK: ", jhmiSK)
    hyb_abema.keygen(gp, jhuSK,'jhu.professor', bobs_gid, K)
    #hyb_abema.keygen(gp, jhuSK,jhu_attributes, bobs_gid, K) # Does not work; only one attribute at a time.
    hyb_abema.keygen(gp, jhmiSK,'jhmi.researcher', bobs_gid, K)
    hyb_abema.keygen(gp, jhuSK,'jhu.professor', bobs_gid, Ksame)
    hyb_abema.keygen(gp, jhmiSK,'jhmi.researcher', bobs_gid, Ksame)

    # Let's set up an "alternate" set of ABE secret keys for bob, generated with the same attributes but with a different
    # gp. Let's see whether decryption is successful using different combinations of gp.
    gpAlternative = hyb_abema.setup()
    Kalternative = {}
    hyb_abema.keygen(gpAlternative, jhuSK, 'jhu.professor', bobs_gid, Kalternative)
    hyb_abema.keygen(gpAlternative, jhmiSK,'jhmi.researcher', bobs_gid, Kalternative)
    
    # I will also recreate a set of keys for bob using original gp, such that we check whether these keys decrypt old ciphertexts using same ABE encryption keys and gp.
    Knew = {}
    hyb_abema.keygen(gp, jhuSK,'jhu.professor', bobs_gid, Knew)
    hyb_abema.keygen(gp, jhmiSK,'jhmi.researcher', bobs_gid, Knew)

    msg = b'Hello World, I am a sensitive record!'
    size = len(msg)
    policy_str = "(jhmi.doctor OR (jhmi.researcher AND jhu.professor))"
    #ct = hyb_abema.encrypt(allAuthPK, gp, msg, policy_str)
    #ctAlternative = hyb_abema.encrypt(allAuthPK, gpAlternative, msg, policy_str)
    #ctNewAuthorityKeys = hyb_abema.encrypt(allAuthPKnew, gp, msg, policy_str)
    ct = hyb_abema.encrypt(gp, allAuthPK, msg, policy_str)
    ctAlternative = hyb_abema.encrypt(gpAlternative, allAuthPK, msg, policy_str)
    ctNewAuthorityKeys = hyb_abema.encrypt(gp, allAuthPKnew, msg, policy_str)

    if debug:
        print("Ciphertext")
        print("c1 =>", ct['c1'])
        print("c2 =>", ct['c2'])
        print("\n\nUser secret key K:")
        print(K)
        print("\n\nUser secret key Ksame:")
        print(Ksame)
        print("\n\nPublic keys:")
        print(allAuthPK)
        print("\n\njhuSK key:")
        print(jhuSK)
        print(type(jhuSK['JHU.STUDENT']['alpha_i']))
        print(type(jhuSK['JHU.STUDENT']['y_i']))
        K_json = json.dumps(K, cls=jsonhelper.KeyEncoder, pairingCurve=groupObj.param)
        print("\n\nJSON representation of K:\n", K_json)
        K_fromJson = json.loads(K_json, cls=jsonhelper.KeyDecoder)
        print("\n\nDecoding K from JSON:\n", K_fromJson)
        #json.dumps(K)
        # Let's extract pieces of the secret key and attempt to serialize such that JSON can manipulate them.
        # Use Charm's pairinggroup.PairingGroup serialize and deserialize methods (which are coded in C).
        print("\n\nOne secret key:")
        print(K['JHMI.RESEARCHER']['k'])
        print(K['JHMI.RESEARCHER']['k'].__class__.__name__)
        #print(K['JHMI.RESEARCHER']['k'].__class__.__dict__)
        #print(charm.core.math.pairing.ElementType.__name__)
        print(isinstance(type(K['JHMI.RESEARCHER']['k']), charm.core.math.pairing.__class__))
        # Copy the object to a variable.
        obj = K['JHMI.RESEARCHER']['k']
        print(K['JHMI.RESEARCHER']['k'].__class__.__name__ == 'Element')
        # Test working with a variable.
        print(obj.__class__.__name__ == 'Element')
        print(K['JHMI.RESEARCHER']['k'])
        print("Serialized:")
        serialized_key = groupObj.serialize(K['JHMI.RESEARCHER']['k']).decode()
        print(serialized_key)
        print(type(serialized_key))
        #print(groupObj.Pairing)
        print("Deserialized:")
        print(groupObj.deserialize(serialized_key.encode()))
        # Let's try deserializing with another groupObj, but with same parameter.
        groupObjOther = PairingGroup(groupObj.param)
        print(groupObjOther.deserialize(serialized_key.encode()))
        print("Random 1: ", groupObj.random())
        print("Random 2: ", groupObj.random())
        print("Random 3: ", groupObj.random())

    try:
        print("Decrypting message using gp for both ciphertext and secret keys.")
        orig_msg = hyb_abema.decrypt(gp, K, ct)
        if debug: print("Result =>", orig_msg)
        assert orig_msg == msg, "Failed Decryption!!!"
        if debug: print("Successful Decryption!!!")
    except Exception as e:
        print(e)


    try:
        print("Decrypting message using gp for ciphertext and gpAlternative (Kalternative) for secret keys.")
        orig_msg = hyb_abema.decrypt(gp, Kalternative, ct)
        if debug: print("Result =>", orig_msg)
        assert orig_msg == msg, "Failed Decryption!!!"
        if debug: print("Successful Decryption!!!")
    except Exception as e:
        print(e)

    try:
        print("Decrypting message using gpAlternative for ciphertext and gp for secret keys.")
        orig_msg = hyb_abema.decrypt(gp, K, ctAlternative)
        if debug: print("Result =>", orig_msg)
        assert orig_msg == msg, "Failed Decryption!!!"
        if debug: print("Successful Decryption!!!")
    except Exception as e:
        print(e)


    try:
        print("Decrypting message using gpAlternative for ciphertext and gpAlternative (Kalternative) for secret keys.")
        orig_msg = hyb_abema.decrypt(gp, Kalternative, ctAlternative)
        if debug: print("Result =>", orig_msg)
        assert orig_msg == msg, "Failed Decryption!!!"
        if debug: print("Successful Decryption!!!")
    except Exception as e:
        print(e)

    try:
        print("Decrypting message using gpAlternative for ciphertext and gpAlternative (Kalternative) for secret keys, and gpAlternative for decrypt method.")
        print("Note that authority's ABE secret keys were generated with gp.")
        orig_msg = hyb_abema.decrypt(gpAlternative, Kalternative, ctAlternative)
        if debug: print("Result =>", orig_msg)
        assert orig_msg == msg, "Failed Decryption!!!"
        if debug: print("Successful Decryption!!!")
    except Exception as e:
        print(e)

    try:
        print("Decrypting message using gp for both ciphertext and secret keys, but gpAlternative for decrypt method.")
        orig_msg = hyb_abema.decrypt(gpAlternative, K, ct)
        if debug: print("Result =>", orig_msg)
        assert orig_msg == msg, "Failed Decryption!!!"
        if debug: print("Successful Decryption!!!")
    except Exception as e:
        print(e)
    
    try:
        print("Decrypting message using gp for ciphertext and Knew for secret keys (generated with gp).")
        orig_msg = hyb_abema.decrypt(gp, Knew, ct)
        if debug: print("Result =>", orig_msg)
        assert orig_msg == msg, "Failed Decryption!!!"
        if debug: print("Successful Decryption!!!")
    except Exception as e:
        print(e)
        
    try:
        print("Decrypting message using gp for both ciphertext and secret keys, but a new ciphertext generated with new authority's keys with same attributes.")
        orig_msg = hyb_abema.decrypt(gp, K, ctNewAuthorityKeys)
        if debug: print("Result =>", orig_msg)
        assert orig_msg == msg, "Failed Decryption!!!"
        if debug: print("Successful Decryption!!!")
    except Exception as e:
        print(e)




if __name__ == "__main__":
    debug = True
    main()



# Function to print elements of nested dictionaries. Use as inspiration to serialize pairing.Element things.
#==============================================================================
# def myprint(d):
#   for k, v in d.iteritems():
#     if isinstance(v, dict):
#       myprint(v)
#     else:
#       print "{0} : {1}".format(k, v)
#==============================================================================
