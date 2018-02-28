# -*- coding: utf-8 -*-
"""
Created on Wed Aug 31 16:49:36 2016

@author: locksmith
"""

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

class TestDatabase(unittest.TestCase):

    def setUp(self):
        """
        Create a Service object.
        """
        self.database="locationservicetest.db"
        self.locationServiceObj = locationservice.LocationService(database=self.database)
        #self.assertTrue(locationService)
        
    def testListEntityAttributeTable(self):
        """
        Lists all entities and their attributes per the entity table and entityAttribute table.
        """
        for entityID in locationserviceutility.getAllLikeEntityIDs("%", self.database):
            print("Attributes registered to EntityID: ", entityID)
            print("---------------------------------------------")
            for attribute in locationserviceutility.getAllEntityAttributes(entityID, database=self.database):
                print(attribute)
            print("\n")
            
    def testGenericSelect(self):
        """
        Just some generic select statement.
        """
        entityID = "location.service"
        con = sqlite3.connect(self.database)
        with con:
            results = con.execute("""select * from entityKey where entityFk = """
                                  """(select primaryKey from entity where entityID = ?)""", (entityID,)).fetchall()
        print("Results from SELECT:")
        print(results)
            


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