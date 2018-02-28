# -*- coding: utf-8 -*-
"""
Created on Thu Jul 16 16:46:20 2015

@author: locksmith
"""

import sys
sys.path.append("..")

import unittest
import unittest.mock
import locationservice
import locationserviceutility
import Crypto.Protocol.KDF
import Crypto.Hash.SHA256
import sqlite3
import time
from charm.schemes.abenc.dabe_aw11 import Dabe
from charm.toolbox.pairinggroup import PairingGroup
from charm.adapters.dabenc_adapt_hybrid import HybridABEncMA

class TestLocationService(unittest.TestCase):

    def setUp(self):
        """
        Create a Service object.
        """
        database="locationservicetest.db"
        self.locationServiceObj = locationservice.LocationService(database=database)
        #self.assertTrue(locationService)
       
    def test_SignMessageAndVerify(self):
        """
        Create Location Service X.509 and private key, sign message and verify signature.
        """
        message = b"This is the message to be signed."  
        messageFalse = b"This is a false message to be verified."
        signature = self.locationServiceObj.sign(message)
        #print(signature)
        signatureFalse = bytes(signature[:-2]) # This is a tampered-with signature.
        self.assertEqual(signature, self.locationServiceObj.sign(message)) # Test whether the same signature is generated for the same message as before.
        self.assertTrue(self.locationServiceObj.verify(message, signature))
        self.assertFalse(self.locationServiceObj.verify(messageFalse, signature))
        self.assertFalse(self.locationServiceObj.verify(message, signatureFalse))
        
    def test_generatePasswordHash(self):
        """
        Verify hashes constructed with passwords or secret keys. The key derivation function is PBKDF2-HMAC-SHA256.
        """
        password = "This is my secret password."
        salt = b'thisSalt'
        #generatePasswordHash(self, password, salt, dkLength=32, count=100000, digestmodule=Crypto.Hash.SHA256)
        # Generate a hash directly, compare with function.
        self.assertEqual(Crypto.Protocol.KDF.PBKDF2(password, salt, dkLen=32, count=4096, prf=lambda p, s: Crypto.Hash.HMAC.new(p,s,Crypto.Hash.SHA256).digest()),
                         self.locationServiceObj.generatePasswordHashPBKDF2(password, salt))
        # Generate a hash using SHA1, compare with function (should not match).
        self.assertNotEqual(Crypto.Protocol.KDF.PBKDF2(password, salt, dkLen=32, count=4096),
                         self.locationServiceObj.generatePasswordHashPBKDF2(password, salt))
        # Generate a hash with different count and compare with function (should not match).
        self.assertNotEqual(Crypto.Protocol.KDF.PBKDF2(password, salt, dkLen=32, count=4097, prf=lambda p, s: Crypto.Hash.HMAC.new(p,s,Crypto.Hash.SHA256).digest()),
                         self.locationServiceObj.generatePasswordHashPBKDF2(password, salt))
        # Generate two hashes with different salts and same password, verify.
        hash1 = self.locationServiceObj.generatePasswordHashPBKDF2(password, salt)
        hash2 = self.locationServiceObj.generatePasswordHashPBKDF2(password, b'notsalt!')
        self.assertNotEqual(hash1, hash2)
        # Generate two hashes with different passwords and same salt, verify.
        hash1 = self.locationServiceObj.generatePasswordHashPBKDF2("This is NOT the secret password.", salt)
        hash2 = self.locationServiceObj.generatePasswordHashPBKDF2(password, salt)
        self.assertNotEqual(hash1, hash2)
        # Finally, check the length of hash.
        self.assertEqual(32, len(hash1))
        
            
    def test_registerEntityAttribute(self):
        """
        Tests registration of entity attributes (by string) to the database (table entityattribute).
        """
        database="locationservicetest.db"
        
        # Let's pick a entity and a few attributes, and register those attributes to that entity.
        entityID = "douggiehowser@princeton.edu"
        attributes = ["global.payment.visa", "global.payment.androidpay",
                      "global.store.amazon.com", "amazon.com.spendinglimit.level2",
                      "amazon.com.vip.prime"]
        
        expiration = time.time() + 1 * 7 * 24 * 60 * 60 # One week expiration.
        # First, erase any attributes for entityID. Then, insert the attributes listed here.
        con = sqlite3.connect(database)
        with con:
            con.execute("delete from entityAttribute where entityFk= (select primaryKey from entity where entityID=?)", (entityID,))
        
        for attribute in attributes:
            self.locationServiceObj.registerEntityAttribute(entityID, attribute, expirationEpoch=expiration,
                                                              database=database)
                                                              
        # Now, let's compare whether all registered entity attributes, in the database, are those listed here.
        attributesInDatabase = self.locationServiceObj.getAllEntityAttributes(entityID, database=database)
        #print(attributesInDatabase)
        self.assertTrue(set(attributes) == set(attributesInDatabase))
        
    def test_updateEntityAttribute(self):
        """
        Tests whether the registerEntityAttribute works well when an attribute already exists, in which case
        the lastUpdatedEpoch of the existing table row is updated.
        """
        database = "locationservicetest.db"
        # Let's pick a entity and one new attribute, register this attribute such that we can check the lastUpdatedEpoch later.
        entityID = "douggiehowser@princeton.edu"
        attribute = "bestbuy.com.vip.platinum"
        
        originalExpiration = time.time() + 1 * 7 * 24 * 60 * 60 # One week expiration.
        con = sqlite3.connect(database)
        # First, register the new attribute.
        self.locationServiceObj.registerEntityAttribute(entityID, attribute, expirationEpoch=originalExpiration, database=database)
        # Now, retrieve the lastUpdatedEpoch of the newly created entity attribute and store it for comparison.
        with con:
            originalLastUpdatedEpoch = con.execute("""select lastUpdatedEpoch from entityAttribute where attributeFk= """
                                                   """(select primaryKey from attribute where attribute=?) and """
                                                   """entityFk=(select primaryKey from entity where entityID=?)""", (attribute,entityID)).fetchall()
        originalLastUpdatedEpoch = originalLastUpdatedEpoch[0][0]
            
        # Now register the same attribute again for the entity, which will only update its lastUpdatedEpoch and expiration.
        # Assume the execution of this code will spend a few miliseconds and, as such, the lastUpdatedEpoch will differ.
        updatedExpiration = time.time() + 2 * 7 * 24 * 60 * 60 # Two weeks expiration.
        self.locationServiceObj.registerEntityAttribute(entityID, attribute, expirationEpoch=updatedExpiration, database=database)
        # Now retrieve the row's new expiration and updated epochs.
        with con:
            result = con.execute("""select expirationEpoch, lastUpdatedEpoch from entityAttribute where attributeFk= """
                                 """(select primaryKey from attribute where attribute=?) and """
                                 """entityFk=(select primaryKey from entity where entityID=?)""", (attribute,entityID)).fetchall()
        updatedExpiration = result[0][0]
        updatedLastUpdatedEpoch = result[0][1]
        #print(originalExpiration, updatedExpiration)
        #print(originalLastUpdatedEpoch, updatedLastUpdatedEpoch)
        # Finally, compare the original and updated values. They should differ.
        self.assertNotEqual(originalExpiration, updatedExpiration)
        self.assertNotEqual(originalLastUpdatedEpoch, updatedLastUpdatedEpoch)
        
    def test_getAllLikeAttributes(self):
        """
        Tests the function that returns a list of attributes matching a certain search string.
        """
        database = "locationservicetest.db"
        searchString = "amazon.com%" # Begin with this.
        attributes = self.locationServiceObj.getAllLikeAttributes(searchString, database=database)
        # Add a bogus element to the returned list to prove the final assertion.
        #attributes.append("baba")
        #print(attributes)
        # This will assert that each element in the returned list of attributes does contain the searchString.
        # Remove the final '%' character such that the test works in python.
        self.assertTrue(all(searchString[:-1] in attribute for attribute in attributes))
        
    def test_generateBnonce(self):
        """
        Tests the generation of the BNONCE, an ABE-encrypted random nonce.
        """
        accessPolicy = "(global.payment.visa OR global.payment.androidpay) AND amazon.com.spendinglimit.level2"
        entityIDlist = [self.locationServiceObj.entityID, 'amazon.com']
        
        nb, bnonceSerialized, bnonceSignature = self.locationServiceObj.generateBnonce(entityIDlist, accessPolicy)
        # Verify the signed bnonce.
        self.assertTrue(self.locationServiceObj.verify(bnonceSerialized, bnonceSignature))
        
    def test_getCertificateAsString(self):
        """
        Tests the function that returns the Location Service certificate as a string.
        """
        print(self.locationServiceObj.getCertificateAsString())
        
    def tearDown(self):
        pass
    
    #Crypto.Protocol.KDF.PBKDF2("blablabla", b"xa", prf=lambda p, s: Crypto.Hash.HMAC.new(p,s,Crypto.Hash.SHA256).digest())
    #print(len(Crypto.Protocol.KDF.PBKDF2("blablabla", b"xa", prf=lambda p, s: Crypto.Hash.HMAC.new(p,s,Crypto.Hash.SHA256).digest())))
    
if __name__ == '__main__':
    unittest.main(verbosity=2)






#opensslsignature = OpenSSL.crypto.sign(opensslkey, "blablabla", 'sha256')
#print("Signature: ", opensslsignature)
#try:
#    print("Verify? ", OpenSSL.crypto.verify(cert, opensslsignature, "blablabla", 'sha256'))
#except:
#    print("Bad signature!")