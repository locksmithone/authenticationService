# -*- coding: utf-8 -*-
"""
Created on Wed Jun 24 15:31:05 2015

@author: locksmith
"""

import sys
sys.path.append("..")
import unittest
import unittest.mock
import onetimepass
import base64
import string
import random
import locationserviceutility
import sqlite3
import constants
import time
import json
import jsonhelper
import itertools
import locationservice
import Crypto.Random.random
import struct
import useragent
import useragentsimulator
import math
import charm.toolbox.symcrypto

#from bluetoothlayer import BluetoothNetService
#from netservicetype import NetServiceType
#import bluetooth

class TestLocationServiceUtility(unittest.TestCase):

    def setUp(self):
        self.databaseLocationService = "locationservicetest.db"
        self.locationServiceObj = locationservice.LocationService(database=self.databaseLocationService)
        # Set up locationserviceutility mock.
        self.patcher = unittest.mock.patch('locationserviceutility.receiveMessage', autospec = True)
        self.mock_locationserviceutility = self.patcher.start()
        self.addCleanup(self.patcher.stop)


    def test_generateTotpRandomSecret(self):
        length = constants.TOTP_SEED_LENGTH_BITS # Length of random string in bits.
        # Generate a random string of any uppercase and lowercase characters plus digits, of 'length' length.
        # Note that the random generation within the tested method *is* different: it relies on the PyCrypto libraries.
        randomSecret = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length//8))
        self.assertEqual(len(randomSecret), length//8)
        # Encode the randomSecret in base32 to make it TOTP-compatible.
        randomSecretBase32 = base64.b32encode(randomSecret.encode())
        #print(len(randomSecretBase32))
        # Now do some comparisons with the output of the generateTotpRandomSecret.
        # Lengths of encoded strings must be the same here.
        self.assertEqual(len(randomSecretBase32), len(locationserviceutility.generateTotpRandomSecret(length)))
        # Lengths of decoded strings must be the same.
        self.assertEqual(len(randomSecret), len(base64.b32decode(locationserviceutility.generateTotpRandomSecret(length))))

    def test_registerKeyToDatabase(self):
        """
        Test registration of new keys to the database.
        Keys can be password hashes, TOTP seeds, shared secrets...
        Will not use Mocks, will indeed record things to a test database. The test database locationservicetest.db must exist with some data,
        otherwise error.
        """
        database = "locationservicetest.db"

        # Let's tests operations with password hashes.
        # Create a hash for some password.
        password = "This is my secret password."
        salt = b'thisSalt'
        hash_ = self.locationServiceObj.generatePasswordHashPBKDF2(password, salt)
        entityID = "mrrobot@fsociety.org"
        keyType = constants.PASSWORD_HASH_KEY_TYPE
        algorithm = "PBKDF2-HMAC-SHA256"
        # First, clean the table and fetch the keyTypeID for "Password Hash".
        con = sqlite3.connect(database)
#        with con:
#            con.execute("delete from entityKey")
            #keyTypeFk = con.execute("select primaryKey from keyType where keyType=?", (keyType,)).fetchone()[0]

        # Now register the data. True if successful.
        expiration = time.time() + 10 # 10 seconds.
        self.assertTrue(locationserviceutility.registerKeyToDatabase(entityID, hash_, salt, keyType, algorithm,
                                                                     expirationEpoch=expiration,
                                                                     database=database))
        # Attempt to register the same key again.
        self.assertFalse(locationserviceutility.registerKeyToDatabase(entityID, hash_, salt, keyType, algorithm,
                                                                      expirationEpoch=expiration,
                                                                      database=database))

        # Create another password hash for the same entity. A entity may have many passwords, or not?
        password = "This is another password I have."
        salt = b'othersalt'
        hash_ = self.locationServiceObj.generatePasswordHashPBKDF2(password, salt)
        # Now register the data. True if successful.
        expiration = time.time() + 2 # 2 seconds.
        self.assertTrue(locationserviceutility.registerKeyToDatabase(entityID, hash_, salt, keyType, algorithm, expirationEpoch=expiration, database=database))
        # Try to insert the same data with a different expiration (but the already registered key is still valid), it should not work.
        self.assertFalse(locationserviceutility.registerKeyToDatabase(entityID, hash_, salt, keyType, algorithm, expirationEpoch=expiration*2, database=database))
        # Now insert a key with a very short expiration epoch, let it expire, and attempt to insert the same key/entry.
        salt = b'thisispepper'
        hash_ = self.locationServiceObj.generatePasswordHashPBKDF2(password, salt)
        expiration = time.time() + 10 # 10 seconds.
        self.assertTrue(locationserviceutility.registerKeyToDatabase(entityID, hash_, salt, keyType, algorithm, expirationEpoch=time.time(), database=database))
        time.sleep(1) # Wait one second to allow key to expire. Insertion should return successful.
        self.assertTrue(locationserviceutility.registerKeyToDatabase(entityID, hash_, salt, keyType, algorithm, expirationEpoch=expiration, database=database))
#        with con:
#            foundOne = False
#            result = con.execute("""select key, salt
#                                    from entitykey join keytype on entitykey.keyTypeID = keytype.keyTypeID
#                                    where entitykey.entityID=?
#                                    and entitykey.keyTypeID=?""", (entityID, keyTypeID)).fetchall()
#            print(result)


        # Now simulate a login sequence, wherein a salt is obtained from the entitypassword record for the given entityID, the hash is computed and compared.
        # Key must not be expired. This kind of SQL query must be implemented in the login code.
        password = "This is my secret password."
        salt = b'thisSalt'
        with con:
            foundOne = False
            # It seems ',' instead of 'join' below also works.
            # Comment 2016.07.28. It seems to me the join between tables in the query below is not really necessary... Just query one table, select keyTypeFk from appropriate table just as it was done with entityID primary key.
            result = con.execute("""select key, salt
                                    from entityKey join keyType on entityKey.keyTypeFk = keyType.primaryKey
                                    where entityKey.entityFk in (select primaryKey from entity where entityID=?)
                                    and entityKey.keyTypeFk=(select primaryKey from keyType where keyType=?)
                                    and expirationEpoch > ?""", (entityID, keyType, time.time())).fetchall()
        if not result:
            self.fail("No keys found.")

        # Go through all tuples within result, fetch salt, generate hash from password, compare with result.
        for record in result:
            hash_ = self.locationServiceObj.generatePasswordHashPBKDF2(password, record[1]) # record[1] is the salt.
            # Now use the assert only if the salt is the one expected.
            # This is not how the login would be done in real life, I am just
            # figuring a way to utilize the assert and not have it fail for each unmatched hash.
            if salt == record[1]:
                self.assertEqual(hash_, record[0])
                if not foundOne:
                    foundOne = True # Found a matching hash. Prevent test from failing at end.
                else:
                    # One match has already been found. There should not be another one.
                    self.fail("More than one match found.")

        self.assertTrue(foundOne) # Must have found exactly one matching hash.

        # Now let's test registering TOTP secret seeds.
        totpSeed = self.locationServiceObj.generateTotpRandomSecret()
        keyType = constants.TOTP_SEED_LOCATHE_KEY_TYPE
        algorithm = "TOTP"
        #with con:

        self.assertTrue(locationserviceutility.registerKeyToDatabase(entityID, totpSeed, None, keyType, algorithm, expirationEpoch=expiration, database=database))
        # Attempt to register the same key again.
        self.assertFalse(locationserviceutility.registerKeyToDatabase(entityID, totpSeed, None, keyType, algorithm, expirationEpoch=expiration, database=database))

        # Now test registration of ABE keys.
        authorityID = "amazon.com"
        pairingGroup = 'SS512'
        attributes = ["amazon.com.vip.prime"]
        expirationEpoch = time.time() + 2 # 2 seconds. Create quickly expiring keys such that we can test for the function finding valid existing keys, but also registering new keys in a new unit test.
        key = b"""{"AMAZON.COM.VIP.PRIME": {"e(gg)^alpha_i": {"__class__": "pairing.Element", "__value__": "3:testkey=", "__pairingCurve__": "SS512"}}}"""
        keyType = constants.ABE_AUTHORITY_PUBLIC_KEY_TYPE
        self.assertTrue(locationserviceutility.registerKeyToDatabase(authorityID, key, None, keyType, "DABE_AW11", expirationEpoch=expirationEpoch, database=database))
        # Attempt to register the same key again.
        self.assertFalse(locationserviceutility.registerKeyToDatabase(authorityID, key, None, keyType, "DABE_AW11", expirationEpoch=expirationEpoch, database=database))


    @unittest.mock.patch('onetimepass.time', autospec=True)
    def test_verifyValidTotp(self, mock_onetimepass_time):
        """
        Given a secret, generate a few TOTPs and verify them from time to time to assert they expire.
        """
        length = constants.TOTP_SEED_LENGTH_BITS # Length of secret in bits.
        tokenLength = constants.TOTP_TOKEN_LENGTH_DIGITS # Length of token in digits.
        timeInterval = constants.TOTP_VALIDITY_INTERVAL_SECONDS # Time interval of token validity in seconds.

        # Generate a secret.
        #secret = locatheregistration.generateTotpRandomSecret(length=length)
        # Use a fixed secret.
        secret = b'2VAVT4HUUG76ZF5RFE3SFT4EDW235RXR3NVB4J2VYXQVNTLA6R2A===='
        # Let's pick a mock time.
        mock_onetimepass_time.time.return_value = 1000 # Will generate 667035372 for the given secret.
        token1000 = onetimepass.get_totp(secret, token_length=tokenLength, interval_length=timeInterval)
        self.assertTrue(onetimepass.valid_totp(token1000, secret, token_length=tokenLength, interval_length=timeInterval))
        self.assertEqual(onetimepass.get_totp(secret, token_length=tokenLength, interval_length=timeInterval), 667035372)
        # Now generate another token 10 seconds later.
        mock_onetimepass_time.time.return_value = 1010
        token1010 = onetimepass.get_totp(secret, token_length=tokenLength, interval_length=timeInterval) # Same 667035372 value as token1000.
        self.assertTrue(onetimepass.valid_totp(token1010, secret, token_length=tokenLength, interval_length=timeInterval))
        self.assertEqual(onetimepass.get_totp(secret, token_length=tokenLength, interval_length=timeInterval), 667035372) # Tokens should be equal within 10 seconds.
        self.assertEqual(token1000, token1010)
        # Now generate another token 35 seconds after the first.
        mock_onetimepass_time.time.return_value = 1035
        token1035 = onetimepass.get_totp(secret, token_length=tokenLength, interval_length=timeInterval) # Generates 2024439888.
        self.assertFalse(onetimepass.valid_totp(token1000, secret, token_length=tokenLength, interval_length=timeInterval))
        self.assertFalse(onetimepass.valid_totp(token1010, secret, token_length=tokenLength, interval_length=timeInterval))
        self.assertTrue(onetimepass.valid_totp(token1035, secret, token_length=tokenLength, interval_length=timeInterval))
        # Tokens should be different, since the first token must have expired after 35 seconds.
        self.assertNotEqual(token1000, token1035)
        self.assertEqual(onetimepass.get_totp(secret, token_length=tokenLength, interval_length=timeInterval), 2024439888)

    def test_registerTotpLocatheSecretSeedToDatabase(self):
        """
        Tests registration of a TOTP secret seed into the SQLite database.
        The specific function for TOTP registration will assume, initially, that only one TOTP secret
        should exist for the pair owner entity/target entity.
        Therefore, the specific TOTP registration will verify this integrity requirement, and then call
        the generic registerKeyToDatabase function.
        """

        length = constants.TOTP_SEED_LENGTH_BITS # Length of secret in bits.
        entityID = "mrrobot@fsociety.org"
        #databaseUser = "locationserviceusertest.db"
        expirationEpoch = time.time() + 2 # 2 seconds.
        # First, expire all valid TOTP keys for the pair owner/target such that we can start clean.
        locationserviceutility.expireTotpLocatheSecretSeeds(entityID, database=self.databaseLocationService)
        #locationserviceutility.expireTotpLocatheSecretSeeds(entityID, database=databaseUser)

        # Now generate a random TOTP seed and register it for the user database and Location Service database.
        totpSeed = locationserviceutility.generateTotpRandomSecret(length)
        # Expect True since all TOTP keys were forcibly expired.
        self.assertTrue(locationserviceutility.registerTotpLocatheSecretSeedToDatabase(entityID,
                                                                                totpSeed,
                                                                                expirationEpoch=expirationEpoch,
                                                                                database=self.databaseLocationService))
        # Now register a new TOTP. It should fail, since there is already a valid one in the database for the entityID.
        # This is the expected behavior now. It might change in the future.
        totpSeedNew = locationserviceutility.generateTotpRandomSecret(length)
        # Expect False since there is already a TOTP seed in the database, registered above.
        self.assertFalse(locationserviceutility.registerTotpLocatheSecretSeedToDatabase(entityID,
                                                                                 totpSeedNew,
                                                                                 expirationEpoch=expirationEpoch,
                                                                                 database=self.databaseLocationService))

    def test_verifyEntityCurrentTotpToken(self):
        """
        Verifies whether the entity generated the correct current TOTP token according to the registered secret seed.
        This unit test tests the function that generates and retrieves a current TOTP token for an entityID, and utilizes
        the onetimepass get_totp to generate and compare the expected generated token directly from onetimepass to the one
        returned by the function.
        """
        length = constants.TOTP_SEED_LENGTH_BITS # Length of secret in bits.
        tokenLength = constants.TOTP_TOKEN_LENGTH_DIGITS # Length of token in digits.
        timeInterval = constants.TOTP_VALIDITY_INTERVAL_SECONDS # Time interval of token validity in seconds.
        entityID = "mrrobot@fsociety.org"
        keyType = constants.TOTP_SEED_LOCATHE_KEY_TYPE
        #databaseUser = "locationserviceusertest.db"
        expirationEpoch = time.time() + 2 # 2 seconds.
        # Make sure there is one, and only one, valid TOTP in the database for the entity.
        # If there are none, create one.
        # Retrieve the registered TOTP secret seed.
        secretSeedList = locationserviceutility.getEntityKeysOfType(entityID, keyType, database=self.databaseLocationService)
        # At the present implementation, there should be at most one TOTP secret per user in the database. Assert this here.
        self.assertTrue(len(secretSeedList) < 2)
        # If the list of returned keys is empty, then simply create a new TOTP seed.
        if len(secretSeedList) == 0:
            # Now generate a random TOTP seed and register it for the user database and Location Service database.
            secretSeed = locationserviceutility.generateTotpRandomSecret(length)
            # Expect True since all TOTP keys were forcibly expired.
            self.assertTrue(locationserviceutility.registerTotpLocatheSecretSeedToDatabase(entityID,
                                                                                    secretSeed,
                                                                                    expirationEpoch=expirationEpoch,
                                                                                    database=self.databaseLocationService))

        else:
            # Otherwise, fetch the seed from the one-item seed.
            secretSeed = secretSeedList[0]
        # Expected TOTP token as calculated by onetimepass.
        expectedCurrentToken = onetimepass.get_totp(secretSeed, token_length=constants.TOTP_TOKEN_LENGTH_DIGITS,
                                                    interval_length=constants.TOTP_VALIDITY_INTERVAL_SECONDS)
        # Calculated token as retrieved seed from database.
        calculatedTokenFromDatabase = locationserviceutility.getEntityCurrentTotpLocatheToken(entityID, database=self.databaseLocationService)
        self.assertEqual(expectedCurrentToken, calculatedTokenFromDatabase)

    def test_getEntityCurrentTotpLocatheTokenForConsistency(self):
        """
        The function getEntityCurrentTotpLocatheToken has consistency checks. Let's test them here.
        """
        length = constants.TOTP_SEED_LENGTH_BITS # Length of secret in bits.
        tokenLength = constants.TOTP_TOKEN_LENGTH_DIGITS # Length of token in digits.
        timeInterval = constants.TOTP_VALIDITY_INTERVAL_SECONDS # Time interval of token validity in seconds.
        entityID = "mrrobot@fsociety.org"
        totpSeed1 = b'seed1'
        totpSeed2 = b'seed2'
        expirationEpoch = time.time() + 2 # 2 seconds.

        keyType = constants.TOTP_SEED_LOCATHE_KEY_TYPE
        keyTypePk = locationserviceutility.getKeyTypePk(keyType, database=self.databaseLocationService)
        # Expire TOTP keys and test whether the get function returns None.
        locationserviceutility.expireTotpLocatheSecretSeeds(entityID, database=self.databaseLocationService)
        self.assertIsNone(locationserviceutility.getEntityCurrentTotpLocatheToken(entityID, database=self.databaseLocationService))
        # Now force insertion of two valid TOTP seeds for the entityID, and check whether the get function catches
        # the consistency violation.
        # We will manipulate the database directly, since the functions should not allow violations.
        con = sqlite3.connect(self.databaseLocationService)
        with con:
            # Insert first valid TOTP seed.
            con.execute("""insert into entityKey(entityFk, key, salt, keyTypeFk, algorithm,"""
                        """creationEpoch, expirationEpoch, lastUsedEpoch) values ("""
                        """(select primaryKey from entity where entityID=?),?,?,?,?,?,?,?)""",
                        (entityID, totpSeed1, None, keyTypePk, 'TOTP', time.time(), expirationEpoch, time.time()))

            # Insert second valid TOTP seed.
            con.execute("""insert into entityKey(entityFk, key, salt, keyTypeFk, algorithm,"""
                        """creationEpoch, expirationEpoch, lastUsedEpoch) values ("""
                        """(select primaryKey from entity where entityID=?),?,?,?,?,?,?,?)""",
                        (entityID, totpSeed2, None, keyTypePk, 'TOTP', time.time(), expirationEpoch, time.time()))
        # Now assert that attempting to get a TOTP token will cause consistency violation due to two valid TOTP seeds.
        with self.assertRaises(SystemExit):
            calculatedTokenFromDatabase = locationserviceutility.getEntityCurrentTotpLocatheToken(entityID, database=self.databaseLocationService)

        # Clean up.
        locationserviceutility.expireTotpLocatheSecretSeeds(entityID, database=self.databaseLocationService)

    def test_createEntity(self):
        entityID = "amazon_test.com"
        name = "Amazon"
        entityTypeFk = 1 # Authority.
        database = "locationservicetest.db"
        self.assertTrue(locationserviceutility.createEntity(entityID, name, entityTypeFk, database))
        # Delete this entry such that the test passes in the future.
        con = sqlite3.connect(database)
        with con:
            con.execute("delete from entity where entityID = ?", (entityID,))

    def test_getAllLikeEntityIDs(self):
        entityID = ["amazon.com", "bestbuy.com"]
        entitySearchString = ["amazon%", "%bestbuy%"]
        for i in range(0, 1):
            self.assertEqual(locationserviceutility.getAllLikeEntityIDs(entitySearchString[i], database=self.databaseLocationService)[0], entityID[i])

    def test_convertJsonIntoListOfSingletonJson(self):
        """
        Test the function that separates key-value pairs within a JSON object into a list of singleton JSON key-value pairs.
        """

        userAbeSecretKeyJson = """{"JHMI.RESEARCHER": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:JlLf2SJLUE/cidm+haUhncJEKnGAk6vMZrxVaDjRUDKYGwVGtEvAtLJEYdUdZr0m19zJ6+Shcol+kVboHrKrfQE="}}, "gid": "20110615 bob@gmail.com cryptokey", "JHU.PROFESSOR": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:CqZ0ITPPp+3OoRSqMPGMy6WmaYpdD6Fyj7v+WgxD8MnKhwee8PW+1k37vbXs9qiGqJPPiNM3cPrSRfg33+6S+QE="}}}"""
        userAbeSecretKeyListOfJson = ["""{"JHMI.RESEARCHER": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:JlLf2SJLUE/cidm+haUhncJEKnGAk6vMZrxVaDjRUDKYGwVGtEvAtLJEYdUdZr0m19zJ6+Shcol+kVboHrKrfQE="}}}""",
                                      """{"gid": "20110615 bob@gmail.com cryptokey"}""",
                                      """{"JHU.PROFESSOR": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:CqZ0ITPPp+3OoRSqMPGMy6WmaYpdD6Fyj7v+WgxD8MnKhwee8PW+1k37vbXs9qiGqJPPiNM3cPrSRfg33+6S+QE="}}}"""]

        convertedJsonAsList = locationserviceutility.convertJsonIntoListOfSingletonJson(userAbeSecretKeyJson, pairingGroup="SS512")

        # Now must compare each dictionary from the lists to check whether they are the same. Since the order of the items
        # within a JSON object may change, we must directly compare dictionary forms of the JSON objects, and also order
        # the lists to assure an element-to-element comparison will find the "same" elements.
        # See http://stackoverflow.com/questions/1663807/how-can-i-iterate-through-two-lists-in-parallel-in-python
        # Do a quick assert for list lengths, but the zip_longest will take care of this anyway by yielding Nones when
        # lists are exhausted.
        self.assertEqual(len(userAbeSecretKeyListOfJson), len(convertedJsonAsList))
        for userAbeSecretKeyListOfJsonItem, convertedJsonAsListItem in itertools.zip_longest(sorted(userAbeSecretKeyListOfJson), sorted(convertedJsonAsList)):
            userAbeSecretKeyListOfJsonItemDeserialized = json.loads(userAbeSecretKeyListOfJsonItem, cls=jsonhelper.KeyDecoder)
            convertedJsonAsListItemDeserialized = json.loads(convertedJsonAsListItem, cls=jsonhelper.KeyDecoder)
            #print(userAbeSecretKeyListOfJsonItemDeserialized, "\n", convertedJsonAsListItemDeserialized)
            self.assertTrue(userAbeSecretKeyListOfJsonItemDeserialized == convertedJsonAsListItemDeserialized)

        # Assert the non-deserialized PairingGroup objects (maintain them as strings) just for the heck of it.
        for userAbeSecretKeyListOfJsonItem, convertedJsonAsListItem in itertools.zip_longest(sorted(userAbeSecretKeyListOfJson), sorted(convertedJsonAsList)):
            userAbeSecretKeyListOfJsonItemDeserialized = json.loads(userAbeSecretKeyListOfJsonItem) #, cls=jsonhelper.KeyDecoder)
            convertedJsonAsListItemDeserialized = json.loads(convertedJsonAsListItem) #, cls=jsonhelper.KeyDecoder)
            #print(userAbeSecretKeyListOfJsonItemDeserialized, "\n", convertedJsonAsListItemDeserialized)
            self.assertTrue(userAbeSecretKeyListOfJsonItemDeserialized == convertedJsonAsListItemDeserialized)


    def test_getAllAttributesIntersectionTwoEntities(self):
        """
        Tests the function that returns the intersection between sets of registered attributes of two entityIDs.
        """
        entityID = "douggiehowser@princeton.edu"
        attributesBestBuy = ["bestbuy.com.spendinglimit.level1", "bestbuy.com.vip.gold", "bestbuy.com.vip.platinum"]
        attributesAmazon = ["amazon.com.spendinglimit.level2", "amazon.com.vip.prime"]
        attributesLocationService = ["global.payment.visa", "global.payment.androidpay", "global.store.amazon.com"]
        bestBuyID = "bestbuy.com"
        amazonID = "amazon.com"
        locationServiceID = constants.ENTITY_ID_LOCATION_SERVICE
        expirationEpoch = time.time() + 1 * 365 * 24 * 60 * 60 # One year.
        # First, register the attributes to assure they all exist as demonstrated in the list.
        for attribute in attributesBestBuy + attributesAmazon + attributesLocationService:
            locationserviceutility.registerEntityAttribute(entityID, attribute, expirationEpoch=expirationEpoch,
                                                           database=self.databaseLocationService)
        # Now retrieve attributes per authority using the tested function and assert using sets to disregard order.
        self.assertTrue(set(attributesBestBuy) == set(locationserviceutility.getAllAttributesIntersectionTwoEntities(entityID, bestBuyID, database=self.databaseLocationService)))
        self.assertTrue(set(attributesAmazon) == set(locationserviceutility.getAllAttributesIntersectionTwoEntities(entityID, amazonID, database=self.databaseLocationService)))
        self.assertTrue(set(attributesLocationService) == set(locationserviceutility.getAllAttributesIntersectionTwoEntities(entityID, locationServiceID, database=self.databaseLocationService)))

    def test_getEntityKeysOfTypeWholeTuple(self):
        """
        Test function that retrieves the whole entityKey tuple.
        """
        entityID = "douggiehowser@princeton.edu"
        keyType = constants.ABE_USER_SECRET_KEY_TYPE
        keyTypeFk = locationserviceutility.getKeyTypePk(keyType, database=self.databaseLocationService)
        creationEpoch = time.time()
        expirationEpoch = creationEpoch + 2 # 2 seconds expiration.
        lastUsedEpoch = creationEpoch
#        testTuples = [(441000, entityID, '{"BESTBUY.COM.SPENDINGLIMIT.LEVEL1": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:pFlZCy/1369E8MlMi05FxN6FCBbDLCfSEnFgZLYWurmj9SFpFHkSPEe18/7QhlQBY9xpbNM70tDGOMg9gjYjrQA="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch),
#                      (442000, entityID, '{"BESTBUY.COM.VIP.GOLD": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:ZxI0nTd9hiXPT0O5iVvUn4Khc3GtF75j09V0drLZoPg6dCl3/fo+CPXpZFbO6aMMxeGH3pxjiiJ67ezsNAFPKQE="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch),
#                      (443000, entityID, '{"BESTBUY.COM.VIP.PLATINUM": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:LF7TXVTm76//vNg3JwiZjhmGwnG1xKHzKvvGV4chskAchTsQnJXXHMCdtM2qkr68x52bzU/9t4Ob9Qh/kC1LeAE="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch),
#                      (444000, entityID, '{"AMAZON.COM.SPENDINGLIMIT.LEVEL2": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:kLld+tXgkA5RU5b0sZ/zWaTrltMU+XnvBeCRnHs6jcD0GTe4TwcQdUcVmCkmAmcBa2d8xpyJRGL/K+P7SKCc0wE="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch),
#                      (445000, entityID, '{"AMAZON.COM.VIP.PRIME": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:Q/JfE5qe/p8yN+lgQcQbpbRgx0RhGZ/jOij3WaEO0okQDhmChxNn4EIYijHgPmpJLWx7XCShM9rE4KnDUDhWcQA="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch),
#                      (446000, entityID, '{"GLOBAL.PAYMENT.VISA": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:IUOU50I8IEWyLtSnIgYH5trxp2P5Q90l3igAnkZ12cRJCxjwo+LkWrjTeJ/0Arqzv/U0WQe6edAEZwnHDGyZgwA="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch),
#                      (447000, entityID, '{"GLOBAL.PAYMENT.ANDROIDPAY": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:jxxikKa1It+ERYeJVnLD+0l5k7JacvMPf0Us02mHSboZBLuoZdHJWvKTJ/kZjBcJdrk7mYJzupAd8a3MNC8migE="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch),
#                      (448000, entityID, '{"GLOBAL.STORE.AMAZON.COM": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:QpRhE8XJ+ErrX5QBjTze3a3BqKbPGDCiwFRyV2I/VSLSameTQPj9t1rL2Y7Mjs5zo/2dtef3x8lbzSrh4WX/jwA="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch)]
        # Manually insert entityKey tuples here to ensure the tests will perform as expected.
        testTuples = [(entityID, '{"BESTBUY.COM.SPENDINGLIMIT.LEVEL1": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:pFlZCy/1369E8MlMi05FxN6FCBbDLCfSEnFgZLYWurmj9SFpFHkSPEe18/7QhlQBY9xpbNM70tDGOMg9gjYjrQA="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch),
                      (entityID, '{"BESTBUY.COM.VIP.GOLD": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:ZxI0nTd9hiXPT0O5iVvUn4Khc3GtF75j09V0drLZoPg6dCl3/fo+CPXpZFbO6aMMxeGH3pxjiiJ67ezsNAFPKQE="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch),
                      (entityID, '{"BESTBUY.COM.VIP.PLATINUM": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:LF7TXVTm76//vNg3JwiZjhmGwnG1xKHzKvvGV4chskAchTsQnJXXHMCdtM2qkr68x52bzU/9t4Ob9Qh/kC1LeAE="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch),
                      (entityID, '{"AMAZON.COM.SPENDINGLIMIT.LEVEL2": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:kLld+tXgkA5RU5b0sZ/zWaTrltMU+XnvBeCRnHs6jcD0GTe4TwcQdUcVmCkmAmcBa2d8xpyJRGL/K+P7SKCc0wE="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch),
                      (entityID, '{"AMAZON.COM.VIP.PRIME": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:Q/JfE5qe/p8yN+lgQcQbpbRgx0RhGZ/jOij3WaEO0okQDhmChxNn4EIYijHgPmpJLWx7XCShM9rE4KnDUDhWcQA="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch),
                      (entityID, '{"GLOBAL.PAYMENT.VISA": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:IUOU50I8IEWyLtSnIgYH5trxp2P5Q90l3igAnkZ12cRJCxjwo+LkWrjTeJ/0Arqzv/U0WQe6edAEZwnHDGyZgwA="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch),
                      (entityID, '{"GLOBAL.PAYMENT.ANDROIDPAY": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:jxxikKa1It+ERYeJVnLD+0l5k7JacvMPf0Us02mHSboZBLuoZdHJWvKTJ/kZjBcJdrk7mYJzupAd8a3MNC8migE="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch),
                      (entityID, '{"GLOBAL.STORE.AMAZON.COM": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:QpRhE8XJ+ErrX5QBjTze3a3BqKbPGDCiwFRyV2I/VSLSameTQPj9t1rL2Y7Mjs5zo/2dtef3x8lbzSrh4WX/jwA="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch)]

        script = """
                INSERT INTO entityKey (primaryKey, entityFk, "key", salt, keyTypeFk, algorithm, creationEpoch, expirationEpoch, lastUsedEpoch) VALUES (441000, 3, '{"BESTBUY.COM.SPENDINGLIMIT.LEVEL1": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:pFlZCy/1369E8MlMi05FxN6FCBbDLCfSEnFgZLYWurmj9SFpFHkSPEe18/7QhlQBY9xpbNM70tDGOMg9gjYjrQA="}}}', NULL, 7, 'DABE_AW11', 1.4764e+09, 1.4764e+09, 1.4764e+09);
                INSERT INTO entityKey (primaryKey, entityFk, "key", salt, keyTypeFk, algorithm, creationEpoch, expirationEpoch, lastUsedEpoch) VALUES (442000, 3, '{"BESTBUY.COM.VIP.GOLD": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:ZxI0nTd9hiXPT0O5iVvUn4Khc3GtF75j09V0drLZoPg6dCl3/fo+CPXpZFbO6aMMxeGH3pxjiiJ67ezsNAFPKQE="}}}', NULL, 7, 'DABE_AW11', 1.4764e+09, 1.4764e+09, 1.4764e+09);
                INSERT INTO entityKey (primaryKey, entityFk, "key", salt, keyTypeFk, algorithm, creationEpoch, expirationEpoch, lastUsedEpoch) VALUES (443000, 3, '{"BESTBUY.COM.VIP.PLATINUM": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:LF7TXVTm76//vNg3JwiZjhmGwnG1xKHzKvvGV4chskAchTsQnJXXHMCdtM2qkr68x52bzU/9t4Ob9Qh/kC1LeAE="}}}', NULL, 7, 'DABE_AW11', 1.4764e+09, 1.4764e+09, 1.4764e+09);
                INSERT INTO entityKey (primaryKey, entityFk, "key", salt, keyTypeFk, algorithm, creationEpoch, expirationEpoch, lastUsedEpoch) VALUES (444000, 3, '{"AMAZON.COM.SPENDINGLIMIT.LEVEL2": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:kLld+tXgkA5RU5b0sZ/zWaTrltMU+XnvBeCRnHs6jcD0GTe4TwcQdUcVmCkmAmcBa2d8xpyJRGL/K+P7SKCc0wE="}}}', NULL, 7, 'DABE_AW11', 1.4764e+09, 1.4764e+09, 1.4764e+09);
                INSERT INTO entityKey (primaryKey, entityFk, "key", salt, keyTypeFk, algorithm, creationEpoch, expirationEpoch, lastUsedEpoch) VALUES (445000, 3, '{"AMAZON.COM.VIP.PRIME": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:Q/JfE5qe/p8yN+lgQcQbpbRgx0RhGZ/jOij3WaEO0okQDhmChxNn4EIYijHgPmpJLWx7XCShM9rE4KnDUDhWcQA="}}}', NULL, 7, 'DABE_AW11', 1.4764e+09, 1.4764e+09, 1.4764e+09);
                INSERT INTO entityKey (primaryKey, entityFk, "key", salt, keyTypeFk, algorithm, creationEpoch, expirationEpoch, lastUsedEpoch) VALUES (446000, 3, '{"GLOBAL.PAYMENT.VISA": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:IUOU50I8IEWyLtSnIgYH5trxp2P5Q90l3igAnkZ12cRJCxjwo+LkWrjTeJ/0Arqzv/U0WQe6edAEZwnHDGyZgwA="}}}', NULL, 7, 'DABE_AW11', 1.4764e+09, 1.4764e+09, 1.4764e+09);
                INSERT INTO entityKey (primaryKey, entityFk, "key", salt, keyTypeFk, algorithm, creationEpoch, expirationEpoch, lastUsedEpoch) VALUES (447000, 3, '{"GLOBAL.PAYMENT.ANDROIDPAY": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:jxxikKa1It+ERYeJVnLD+0l5k7JacvMPf0Us02mHSboZBLuoZdHJWvKTJ/kZjBcJdrk7mYJzupAd8a3MNC8migE="}}}', NULL, 7, 'DABE_AW11', 1.4764e+09, 1.4764e+09, 1.4764e+09);
                INSERT INTO entityKey (primaryKey, entityFk, "key", salt, keyTypeFk, algorithm, creationEpoch, expirationEpoch, lastUsedEpoch) VALUES (448000, 3, '{"GLOBAL.STORE.AMAZON.COM": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:QpRhE8XJ+ErrX5QBjTze3a3BqKbPGDCiwFRyV2I/VSLSameTQPj9t1rL2Y7Mjs5zo/2dtef3x8lbzSrh4WX/jwA="}}}', NULL, 7, 'DABE_AW11', 1.4764e+09, 1.4764e+09, 1.4764e+09);
                """
        con = sqlite3.connect(self.databaseLocationService)
        # Insert the rows with known values.
        with con:
            con.executemany("""insert into entityKey (entityFk, "key", salt, keyTypeFk, algorithm, creationEpoch, expirationEpoch, lastUsedEpoch) values((select primaryKey from entity where entityID=?),?,?,?,?,?,?,?)""", testTuples)
        # Fetch the rows with the tested function. Fetch them twice, such that the last retrieved value of lastUsedEpoch
        # is actually the value closest to the current time.time(). Remember that the retrieved lastUsedEpoch is the value
        # *before* the lastUsedEpoch field is updated. As such, in this test, fetching only once would result in a
        # lastUsedEpoch = creationEpoch.
        existingRows = locationserviceutility.getEntityKeysOfTypeWholeTuple(entityID, keyType, database=self.databaseLocationService)
        # Yes, fetch twice. See comment above.
        existingRows = locationserviceutility.getEntityKeysOfTypeWholeTuple(entityID, keyType, database=self.databaseLocationService)
        # Now check for each retrieved row, if it exists in the inserted ones previously.
        # Also check whether the lastUsedEpoch was updated: it should be > creationEpoch.
        for row in existingRows:
            #print(row.keys())
            # The key index in testTuples is [1].
            self.assertTrue(any(row['key'] == testTuplesItem[1] for testTuplesItem in testTuples))
            self.assertTrue(row['lastUsedEpoch'] > creationEpoch)
            # Assert that there are no "extra" rows retrieved, only those manually inserted here.
            self.assertEqual(len(testTuples), len(existingRows))
        # Now fetch the rows again using the function, but force an early notExpiredBeforeEpoch.
        existingRows = locationserviceutility.getEntityKeysOfTypeWholeTuple(entityID, keyType, notExpiredBeforeEpoch=expirationEpoch + 10, database=self.databaseLocationService)
        # The return should be an empty list.
        self.assertEqual(existingRows, [])
        # Let the keys expire.
        time.sleep(expirationEpoch - creationEpoch)

    def test_getEntityKeysOfType(self):
        """
        Test function that retrieves keys.
        """
        entityID = "douggiehowser@princeton.edu"
        keyType = constants.ABE_USER_SECRET_KEY_TYPE
        keyTypeFk = locationserviceutility.getKeyTypePk(keyType, database=self.databaseLocationService)
        creationEpoch = time.time()
        expirationEpoch = creationEpoch + 2 # 2 seconds expiration.
        lastUsedEpoch = creationEpoch
        # Manually insert entityKey tuples here to ensure the tests will perform as expected.
        testTuples = [(entityID, '{"BESTBUY.COM.SPENDINGLIMIT.LEVEL1": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:pFlZCy/1369E8MlMi05FxN6FCBbDLCfSEnFgZLYWurmj9SFpFHkSPEe18/7QhlQBY9xpbNM70tDGOMg9gjYjrQA="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch),
                      (entityID, '{"BESTBUY.COM.VIP.GOLD": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:ZxI0nTd9hiXPT0O5iVvUn4Khc3GtF75j09V0drLZoPg6dCl3/fo+CPXpZFbO6aMMxeGH3pxjiiJ67ezsNAFPKQE="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch),
                      (entityID, '{"BESTBUY.COM.VIP.PLATINUM": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:LF7TXVTm76//vNg3JwiZjhmGwnG1xKHzKvvGV4chskAchTsQnJXXHMCdtM2qkr68x52bzU/9t4Ob9Qh/kC1LeAE="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch),
                      (entityID, '{"AMAZON.COM.SPENDINGLIMIT.LEVEL2": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:kLld+tXgkA5RU5b0sZ/zWaTrltMU+XnvBeCRnHs6jcD0GTe4TwcQdUcVmCkmAmcBa2d8xpyJRGL/K+P7SKCc0wE="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch),
                      (entityID, '{"AMAZON.COM.VIP.PRIME": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:Q/JfE5qe/p8yN+lgQcQbpbRgx0RhGZ/jOij3WaEO0okQDhmChxNn4EIYijHgPmpJLWx7XCShM9rE4KnDUDhWcQA="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch),
                      (entityID, '{"GLOBAL.PAYMENT.VISA": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:IUOU50I8IEWyLtSnIgYH5trxp2P5Q90l3igAnkZ12cRJCxjwo+LkWrjTeJ/0Arqzv/U0WQe6edAEZwnHDGyZgwA="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch),
                      (entityID, '{"GLOBAL.PAYMENT.ANDROIDPAY": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:jxxikKa1It+ERYeJVnLD+0l5k7JacvMPf0Us02mHSboZBLuoZdHJWvKTJ/kZjBcJdrk7mYJzupAd8a3MNC8migE="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch),
                      (entityID, '{"GLOBAL.STORE.AMAZON.COM": {"k": {"__pairingCurve__": "SS512", "__class__": "pairing.Element", "__value__": "1:QpRhE8XJ+ErrX5QBjTze3a3BqKbPGDCiwFRyV2I/VSLSameTQPj9t1rL2Y7Mjs5zo/2dtef3x8lbzSrh4WX/jwA="}}}', None, keyTypeFk, 'DABE_AW11', creationEpoch, expirationEpoch, lastUsedEpoch)]

        con = sqlite3.connect(self.databaseLocationService)
        # Insert the rows with known values.
        with con:
            con.executemany("""insert into entityKey (entityFk, "key", salt, keyTypeFk, algorithm, creationEpoch, expirationEpoch, lastUsedEpoch) values((select primaryKey from entity where entityID=?),?,?,?,?,?,?,?)""", testTuples)
        # Fetch the rows with the tested function. Force a lastUsedEpoch.
        lastUsedEpoch = 1000.0
        existingKeys = locationserviceutility.getEntityKeysOfType(entityID, keyType, lastUsedEpoch=lastUsedEpoch, database=self.databaseLocationService)
        # Now check for each retrieved key, if it exists in the inserted ones previously.
        for key in existingKeys:
            # The key index in testTuples is [1].
            self.assertTrue(any(key == testTuplesItem[1] for testTuplesItem in testTuples))
            # Assert that only the manually inserted keys were retrieved (at least the same quantity).
            self.assertEqual(len(testTuples), len(existingKeys))
            # Manually select the same row in the database, in particular to check whether lastUsedEpoch was correctly updated.
            # We must use a manual query such that the lastUsedEpoch does not get touched again by the function.
            with con:
                retrievedLastUsedEpoch = con.execute("""select lastUsedEpoch from entityKey where """
                                                     """entityFk=(select primaryKey from entity where entityID=?) and """
                                                     """keyTypeFk in (select primaryKey from keyType where keyType=?) and """
                                                     """expirationEpoch > ?""",
                                                     (entityID, keyType, time.time())).fetchall()
            # Note that the result of the query is something like ((epoch,)).
            self.assertEqual(retrievedLastUsedEpoch[0][0], lastUsedEpoch)
        # Now fetch the rows again using the function, but force an early notExpiredBeforeEpoch.
        existingKeys = locationserviceutility.getEntityKeysOfType(entityID, keyType, notExpiredBeforeEpoch=expirationEpoch + 10, database=self.databaseLocationService)
        # The return should be an empty list.
        self.assertEqual(existingKeys, [])
        # Let the keys expire.
        time.sleep(expirationEpoch - creationEpoch)

    def test_copyKeysFromOriginDatabaseToDestinationDatabase(self):
        """
        Tests the function that copies rows from entityKey from one database to other database.
        Example: get ABE public keys from one database and copy to another database.
        """
        fromDatabase = "locationservicetest.db"
        toDatabase = "locationserviceauthoritytest.db"
        # Create a hash for some password.
        password = "This is my secret password."
        salt = b'beautifulSalt'
        hash_ = self.locationServiceObj.generatePasswordHashPBKDF2(password, salt)
        entityID = "mrrobot@fsociety.org"
        keyType = constants.PASSWORD_HASH_KEY_TYPE
        algorithm = "PBKDF2-HMAC-SHA256"
        # Register the key to fromDatabase.
        expiration = time.time() + 10 # 10 seconds.
        self.assertTrue(locationserviceutility.registerKeyToDatabase(entityID, hash_, salt, keyType, algorithm,
                                                                     expirationEpoch=expiration,
                                                                     database=fromDatabase))
        # Try to register again, should fail.
        self.assertFalse(locationserviceutility.registerKeyToDatabase(entityID, hash_, salt, keyType, algorithm,
                                                                      expirationEpoch=expiration,
                                                                      database=fromDatabase))
        password = "This is another secret password."
        salt = b'evenMoreBeautifulSalt'
        hash_ = self.locationServiceObj.generatePasswordHashPBKDF2(password, salt)
        self.assertTrue(locationserviceutility.registerKeyToDatabase(entityID, hash_, salt, keyType, algorithm,
                                                                     expirationEpoch=expiration,
                                                                     database=fromDatabase))
        password = "This is the final secret password."
        salt = b'MagnificentSalt'
        hash_ = self.locationServiceObj.generatePasswordHashPBKDF2(password, salt)
        self.assertTrue(locationserviceutility.registerKeyToDatabase(entityID, hash_, salt, keyType, algorithm,
                                                                     expirationEpoch=expiration,
                                                                     database=fromDatabase))
        # Now copy the newly created keys to toDatabase. It should work, assuming the keys do not exist there.
        self.assertTrue(locationserviceutility.copyKeysFromOriginDatabaseToDestinationDatabase(entityID, keyType, fromDatabase, toDatabase))
        # Try to copy again, it should fail since the toDatabase already has the keys.
        self.assertFalse(locationserviceutility.copyKeysFromOriginDatabaseToDestinationDatabase(entityID, keyType, fromDatabase, toDatabase))

    def test_computeKexAndNxAndComputeEcdheAndPrfPlus(self):
        """
        Tests three functions to compute values KEi and ki or KEr and kr, the ECDHE values, and the involved PRF+.
        """
        kei, ki, ni = locationserviceutility.computeKexAndNx()
        ker, kr, nr = locationserviceutility.computeKexAndNx()
        # Now use some EC arithmetic to test validit of operations.
        hybridDecentralizedABEObject, globalParameter, groupObject = locationserviceutility.createHybridABEMultiAuthorityObject()
        # What follows is:
        # SharedSecret = ki * kr * G = ki * KEr = kr * KEi
        self.assertEqual((globalParameter['g'] ** ki) ** kr, kei ** kr)
        self.assertEqual(globalParameter['g'] ** (ki * kr), kei ** kr)
        self.assertEqual(globalParameter['g'] ** ki, kei)
        self.assertEqual(globalParameter['g'] ** kr, ker)
        self.assertEqual(kei ** kr, ker ** ki)

        # Test the next function.
        # Pick two random values for SPIi, SPIr.
        spii = Crypto.Random.get_random_bytes(constants.SPI_LENGTH_BYTES)
        spir = Crypto.Random.get_random_bytes(constants.SPI_LENGTH_BYTES)
        sharedSecret, keyMaterial = locationserviceutility.computeEcdheSecrets(kr, kei, ni, nr, spii, spir, outputLengthBits=6*256)
        self.assertEqual(globalParameter['g'] ** (ki * kr), sharedSecret)
        self.assertTrue(len(keyMaterial) == 256 * 6 / 8) # 6 keys of 256 bits each, converted to bytes to match the output of len().


    def test_constructHeaderAndHeaderStructToDict(self):
        """
        Tests the function to aid in constructing a LOCATHE header and extracting the header to a dict.

        Tentatively, the LOCATHE header, adapted from IKEv2, is:

                            1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                       Length (4 octets)                       |  unsigned int
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                       IKE SA Initiator's SPI                  |  8 char
        |                           (8 octets)                          |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                       IKE SA Responder's SPI                  |  8 char
        |                           (8 octets)                          |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |Flags (1 octet)| Exchange Type | MjVer | MnVer | Next Payload  |  char | char | char (both fields) | char
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                   Message Counter (4 octets)                  |  unsigned int
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        The messageType and sender are coded within the Flags field, tentatively as so:

        Flags (1 octet) - Indicates specific options that are set for the
        message.  Presence of options is indicated by the appropriate bit
        in the flags field being set.  The bits are as follows:

            +-+-+-+-+-+-+-+-+
            |X|X|R|X|I|X|X|X|
            +-+-+-+-+-+-+-+-+

        Where:

        *  R (Response) - This bit indicates that this message is a
             response to a message containing the same Message counter.  This bit
             MUST be cleared in all request messages and MUST be set in all
             responses.

        *  I (Initiator) - This bit MUST be set in messages sent by the
             original initiator of the message and MUST be cleared in
             messages sent by the original responder.  It is used by the
             recipient to determine which 8 octets of the SPI were generated
             by the recipient.

        *  X - unused.
        """
        # Let's set a few values.
        #spii, spir, exchangeType, messageType, sender, counter, length
        spii = Crypto.Random.get_random_bytes(constants.SPI_LENGTH_BYTES)
        spir = Crypto.Random.get_random_bytes(constants.SPI_LENGTH_BYTES)
        exchangeType = constants.HEADER_EXCHANGE_TYPE_AUTH1
        messageType = constants.HEADER_MESSAGE_TYPE_RESPONSE
        sender = constants.HEADER_SENDER_TYPE_INITIATOR
        messageCounter = 2
        payloadLength = 1200
        # Let's pick the struct that represents the header.
        # We do no include the length field here, as it will be computed and included automatically by the "send" function
        # and put in front of everything.
        structFormat = constants.HEADER_STRUCT_FORMAT
        # Reset flag to start.
        flags = 0b00000000
        mask = 0b00000000
        if sender:
            mask = mask | constants.HEADER_SENDER_TYPE_BITMASK
        if messageType:
            mask = mask | constants.HEADER_MESSAGE_TYPE_BITMASK
        # The final mask should be, here, 0b00101000
        flags = flags | mask
        # Reset all flags that are unused. Not really necessary here the way it is being designed, but let's do it.
        flags = flags & constants.HEADER_FIELD_FLAGS_RESET_UNUSED_MASK
        totalLength = struct.calcsize(constants.HEADER_STRUCT_FORMAT) + payloadLength
        header = struct.pack(structFormat, totalLength, spii, spir, flags.to_bytes(1, byteorder='big'), exchangeType, bytes(1), bytes(1), messageCounter)
        # Now compose the header using the tested function and compare.
        headerFromFunction = locationserviceutility.constructLocatheHeader(spii, spir, exchangeType, messageType, sender, messageCounter, payloadLength)
        self.assertEqual(header, headerFromFunction)
        # Test header length except for the length field (in bytes). The length field is the first one, 4 bytes.
        expectedLength = 4 + 8 + 8 + 1 + 1 + 1 + 1 + 4
        self.assertEqual(len(header), expectedLength)
        self.assertEqual(len(headerFromFunction), expectedLength)
        # Now unpack the header and compare values.
        lengthFromFunction, spiiFromFunction, spirFromFunction, flagsFromFunction, exchangeTypeFromFunction, dummy1, dummy2, messageCounterFromFunction = struct.unpack(constants.HEADER_STRUCT_FORMAT, header)
        self.assertEqual((lengthFromFunction, spiiFromFunction, spirFromFunction, flagsFromFunction, exchangeTypeFromFunction, dummy1, dummy2, messageCounterFromFunction),
                         (totalLength, spii, spir, flags.to_bytes(1, byteorder='big'), exchangeType, bytes(1), bytes(1), messageCounter))
        # Do basically the same by using the function that produces a dict from the header.
        #(lengthFromFunction, spiiFromFunction, spirFromFunction, exchangeType, messageType, sender, messageCounter)
        headerDict = locationserviceutility.headerStructToDict(headerFromFunction)
        # Let's assert the values.
        self.assertEqual(headerDict[constants.HEADER_FIELD_NAME][constants.HEADER_FIELD_NAME_MESSAGE_LENGTH], totalLength)
        self.assertEqual(headerDict[constants.HEADER_FIELD_NAME][constants.HEADER_FIELD_NAME_SPI_I], spii)
        self.assertEqual(headerDict[constants.HEADER_FIELD_NAME][constants.HEADER_FIELD_NAME_SPI_R], spir)
        self.assertEqual(headerDict[constants.HEADER_FIELD_NAME][constants.HEADER_FIELD_NAME_EXCHANGE_TYPE], exchangeType)
        self.assertEqual(headerDict[constants.HEADER_FIELD_NAME][constants.HEADER_FIELD_NAME_SENDER_TYPE], sender)
        self.assertEqual(headerDict[constants.HEADER_FIELD_NAME][constants.HEADER_FIELD_NAME_MESSAGE_COUNTER], messageCounter)

    def test_validateMessageHeader(self):
        """
        The validateMessageHeader function is utilized by LOCATHE agents.
        """
        userDatabase = "locationserviceusertest.db"
        userEntityID = "gialackbar@live.com"
        userAgentObj = useragent.UserAgent(userEntityID, database=userDatabase)

        # Objects for the agent simulators (which will run the protocols simulating real devices/agents).
        userAgentSimulator = useragentsimulator.UserAgentSimulator(userAgentObj)
        # The message is coming from the Location Service.
        messageSerialized = b'\x00\x00\x00j\x00\x00\x00\x00\x00\x00\x00\x00Z\xfc\xdb\xc7pn\x7f\xf3\x00a\x00\x00\x00\x00\x00\x00{"uuid": "10caa7h0-5e12-71ce-010c-a7hebeac0140", "service": "LOCAUTH Service"}'
        message = {'header': {'counter': 0, 'spii': b'\x00\x00\x00\x00\x00\x00\x00\x00', 'message_type': False, 'exchange_type': b'a', 'sender': True, 'length': 106, 'spir': b'Z\xfc\xdb\xc7pn\x7f\xf3'}, 'uuid': '10caa7h0-5e12-71ce-010c-a7hebeac0140', 'service': 'LOCAUTH Service'}
        # The user agent should be in the service advertisement state. Pretent a message was received and now validate it.
        exchangeType = constants.HEADER_EXCHANGE_TYPE_BROADCAST_ECDHE_BLUETOOTH_ADVERTISEMENT
        messageType = constants.HEADER_MESSAGE_TYPE_REQUEST
        # Since we are not using the agent to process the LOCATHE protocol, let's manually set the expected counter value.
        userAgentSimulator.expectedReceivedMessageCounter = 0
        # Now do one header validation with SPI check enforced, and one without SPI check enforcing.
        self.assertFalse(userAgentSimulator.validateMessageHeader(message[constants.HEADER_FIELD_NAME], exchangeType, messageType, enforceSpiCheck=True))
        self.assertTrue(userAgentSimulator.validateMessageHeader(message[constants.HEADER_FIELD_NAME], exchangeType, messageType, enforceSpiCheck=False))

    def test_sendEncryptedMessage(self):
        """
        Tests the function that sends encrypted messages through socket.
        """
        messageList = [{"ker": {"__class__": "pairing.Element", "__value__": "1:D5M+tqPsvfQ2cv1Yt+JRDBtB7OPTndE+/F7hZp0Orrc+3to+Z0HJ4evG+/exABD46qUaVNmITGW4xbvk4YHFZwE=", "__pairingCurve__": "SS512"}, "nr": {"__class__": "bytes", "__value__": "kTTKZNUMXEay/CJ/mq0kuazryJG/AN/SX0nEOP4OG2g="}},
                       {"ker": {"__class__": "pairing.Element", "__value__": "1:D5M+tqPsvfQ2cv1Yt+JRDBtB7OPTndE+/F7hZp0Orrc+3to+Z0HJ4evG+/exABD46qUaVNmITGW4xbvk4YHFZwE=", "__pairingCurve__": "SS512"}, "nr": {"__class__": "bytes", "__value__": "kTTKZNUMXEay/CJ/mq0kuazryJG/AN/SX0nEOP4OG2g="}, 'dummy': 'blablabla'},
                       {"ker": {"__class__": "pairing.Element", "__value__": "1:D5M+tqPsvfQ2cv1Yt+JRDBtB7OPTndE+/F7hZp0Orrc+3to+Z0HJ4evG+/exABD46qUaVNmITGW4xbvk4YHFZwE=", "__pairingCurve__": "SS512"}, "nr": {"__class__": "bytes", "__value__": "kTTKZNUMXEay/CJ/mq0kuazryJG/AN/SX0nEOP4OG2g="}, 'dummy': 'blablablablablablabla'},
                       {"ker": {"__class__": "pairing.Element", "__value__": "1:D5M+tqPsvfQ2cv1Yt+JRDBtB7OPTndE+/F7hZp0Orrc+3to+Z0HJ4evG+/exABD46qUaVNmITGW4xbvk4YHFZwE=", "__pairingCurve__": "SS512"}, "nr": {"__class__": "bytes", "__value__": "kTTKZNUMXEay/CJ/mq0kuazryJG/AN/SX0nEOP4OG2g="}, 'dummy': 'blablablablablablablablablablablablabla'},
                       {'1': 1234453828282, 'first':'dummy string', 10: 828283882, 'another_dummy_string': 'more dummy strings'},
                       {'1': 1234453828282, 'first':'dummy string', 10: 828283882, 'another_dummy_string': 'more dummy strings', 500: 'useless string', 510: {'innerdict':10}, 550: 'spock'}]
        counter = 0
        spii = b'\x00\x00\x00\x00\x00\x00\x00\x10'
        spir = b'Z\xfc\xdb\xc7pn\x7f\xf3'
        messageType = False
        sender = False
        exchangeType = b'a'
        key = b'\x43' * 256
        headerLength = struct.calcsize(constants.HEADER_STRUCT_FORMAT)
        # To estimate encryption length:
        # Calculate PKCS7 padding: pkcs7padded = blockSize - (message % blockSize)
        # Compute base64 overhead: base64encoded = 4 * ceil(pkcs7padded / 3)
        # Add fixed Charm overhead: base64encoded + 194
        for message in messageList:
            payloadSerialized = json.dumps(message, cls=jsonhelper.KeyEncoder, pairingCurve='SS512').encode()
            payloadLength = len(payloadSerialized)
            pkcs7paddedPayloadLength = payloadLength + (constants.AES_BLOCK_SIZE_BYTES - (payloadLength % constants.AES_BLOCK_SIZE_BYTES))
            base64overheadAddedPayloadLength = 4 * math.ceil(pkcs7paddedPayloadLength / 3)
            estimatedEncryptedPayloadLength = base64overheadAddedPayloadLength + constants.CHARM_AUTHENTICATEDCRYPTOABSTRACTION_FIXED_OVERHEAD_BYTES
            sentMessage = locationserviceutility.sendEncryptedMessage(spii, spir, exchangeType, messageType, sender, counter, message, len, 'SS512', key)
            #print("message in messageList:\n", sentMessage)
            self.assertEqual(len(sentMessage), estimatedEncryptedPayloadLength + headerLength)

    def test_receiveEncryptedMessage(self):
        """
        Tests receiveEncryptedMessage function.
        """
        encryptedMessageList = [b"""\x00\x00\x02J\x00\x00\x00\x00\x00\x00\x00\x10Z\xfc\xdb\xc7pn\x7f\xf3\x00a\x00\x00\x00\x00\x00\x00{"msg": "{\\"CipherText\\": \\"czUsj2SjB09AnpIDbud9k95eWiMNExMcm+LnfdSkphUT6BKpMzfSSc71JNVBB20/xfPZKu2mma2f9Jn05OGT5bCOXJyKponwQbUlNHE4yBAeoVRzY+JaSafudHkO0ydg4+HK2mbHwblHTZ8SxP1jNTemFXgX++mW25gvhCBNOrhhV6CGe+QSX+nbrCEnhSs+1r+8wBP9XPn1PBnNHFbBA4BGKZo4ULSm3Ug9XiWd5/mHy/QpRKDE7W8YhXZSmXLXNYasMwI0CtxMvAnVcDmgcKHEb2ULdWTne6tqE5q6CZEU+xuT1ZAdxJMHipvk8oEaJLp7iI72pUFBuOpOeCs+QaF8LlMOnTAnpxk+64T5pNE=\\", \\"MODE\\": 2, \\"IV\\": \\"7Edv/L7AX1uYfSwyUzhsAQ==\\", \\"ALG\\": 0}", "digest": "cfd63ed9597517b5c02ad798206fbc9dae44cfb6add43cb4bff7b3a71d5a9ef3", "alg": "HMAC_SHA2"}""",
                                b"""\x00\x00\x02v\x00\x00\x00\x00\x00\x00\x00\x10Z\xfc\xdb\xc7pn\x7f\xf3\x00a\x00\x00\x00\x00\x00\x00{"msg": "{\\"CipherText\\": \\"qQWflGk6R7iXCaRunNDR78N8386mPOCaO28Tflk1+M7iKiFic6lDthwEc6e3Q14c7lIhAAZAXoAEjIVfyvdjYbwzrRByCOcKJWqUfeM0krZLSWA0zUaE84o3GykNLsZM4cYexMA5jG+jgtErjWfVU/rXgjN6EY6Aka8/iWUox+RBRut0J5a7KgAKKhX69miAru5IL9LwARRbQFskxY2OD1VKjxu3BoEcroYFH7Ndbt9DF7UUoS+R92+V2nm+9z4lWdXvrB1mZ7bC5Dh9/82HkOyYQVIQ8xgYOxRhRQ/N9Js5ThfCkkwjTIAfIiHypJEFdmmTZUNQ9K1nlnwE68NnOq36KwYlAS1Tz7TcKLgwBgQ6X3gSqF3Aq8+q6eHCaqtyKKx9j6Fuwi7EjFS8jGT9vg==\\", \\"MODE\\": 2, \\"IV\\": \\"rvz5ojbRFc4IQeQLMJoKPw==\\", \\"ALG\\": 0}", "digest": "f116c46f134323ca0489c119eb6009f6629a247dcc2f7e9179460569ab8d1be9", "alg": "HMAC_SHA2"}""",
                                b"""\x00\x00\x02v\x00\x00\x00\x00\x00\x00\x00\x10Z\xfc\xdb\xc7pn\x7f\xf3\x00a\x00\x00\x00\x00\x00\x00{"msg": "{\\"CipherText\\": \\"tP8va3uvC8H5OMCB4EGTl2kIk/SXsr8f6LmPfdN6r/S56crcs22Z/BaGG8ULh3iboGFdpUIU8+TT2BKDD88SFQUjqu2taZ2xyWxS9lxrOlkgMvaecuUbT5ZRwaE/bh0lM3uHZXXgVBVYTXjUXoZreXnKEEPi0Yf/750yuQwhMnILVNMfk/5Z21vZAHwAroFB2KFXca6lNlu/f96vpBT2Vs25gB/iTbX62eyKDKHLgQVIDpRJ+VcTsHZEUkODCImL6B5zuPy1bF2UFtd1V7Zq/tHDg0wW89oDgDIzJyHwAl+emytMNfOdgV1sFPCZU4e5Z4ZPb3MW7wmZMsXLdqbBXdTnFS+ti6OCI+ZIO+j+87Pi3NQ4jmWzfCwbsnMgpCggCiPB7M6JEHDsj63rcpHG9A==\\", \\"MODE\\": 2, \\"IV\\": \\"ZN+KvI47hg/6BjnWeXD66w==\\", \\"ALG\\": 0}", "digest": "b8301abcaa1babee7dd8d4edd9577b55fad74e303076227aded2df1b306dc43f", "alg": "HMAC_SHA2"}""",
                                b"""\x00\x00\x02\x9e\x00\x00\x00\x00\x00\x00\x00\x10Z\xfc\xdb\xc7pn\x7f\xf3\x00a\x00\x00\x00\x00\x00\x00{"msg": "{\\"CipherText\\": \\"SKHzjAqooeW2p3UDDRnOW1Z5CJ+oOVd7BGy4dX8P23wTZ7IeqDIVaGcDkibYQ5zKrrGSn0S/c1XhEUpCPykK1u1XxYMyJWvD6iw3I587/LY7sTQzTA1X3aRvQCCnZywZQxAcdW/ySGvduGMz3PQd6qpn4rJg4xFRznvcFhtC6yTqn9Vg+KWdi8XeivT3gAd3gnbcaUiQcp6C5xWWel8diaUJcA64RfhVUCNSYegrqTCtUAHr51eG6tZbFJ4il1WGqYjxj/Uk+mpYMCBlT8tlXgoRXfOT9M+CoX8ay/x3JTULtlAmNztCRNu5u/T7r1zGleb6Ge5H3i4Umz45/Zu35TiMVf1ha2Go1feak+7TYx+eGoAcv/4uOJ72xM6ldtAHTB4MqXUodS1kFQftBA/CBNnWs0W/GAY7hUCwEuSPANZqBT1BDbb11iBxSJXuj7dv\\", \\"MODE\\": 2, \\"IV\\": \\"jusieD2ld+ZSdKHNWdSfUA==\\", \\"ALG\\": 0}", "digest": "aadac9188ece35d9c175ebb4c05d20e3147197e16fd02d5c3976939c84236835", "alg": "HMAC_SHA2"}""",
                                b"""\x00\x00\x01v\x00\x00\x00\x00\x00\x00\x00\x10Z\xfc\xdb\xc7pn\x7f\xf3\x00a\x00\x00\x00\x00\x00\x00{"msg": "{\\"CipherText\\": \\"AARhyiMV7KwKfwPB1kfHSZpOCF2IzMWGKbgjESKanJXBZM/c2VmMA9h+llCNXhFo0HvIpcrxaxZfgqIS641txB2krAhbl9Lndw0p19WNAjwQpXUYNUiJYHCxSuLEB2OYIo3lRpptaNLmhtZSfDrJsw==\\", \\"MODE\\": 2, \\"IV\\": \\"pfSFGGcgSkGW9sv1jbkYJQ==\\", \\"ALG\\": 0}", "digest": "16bd36f98f32165135e8093fa1338f35c65c8b32c2956f5213fc5eb599d01c5e", "alg": "HMAC_SHA2"}""",
                                b"""\x00\x00\x01\xca\x00\x00\x00\x00\x00\x00\x00\x10Z\xfc\xdb\xc7pn\x7f\xf3\x00a\x00\x00\x00\x00\x00\x00{"msg": "{\\"CipherText\\": \\"kPKCqh9sQjnp3ssBahxC4oT3Yd+dqS48TN5mmQ8BB2iTnjnGEpQsEucv1DcunBMnHLMKef2b4eS4CFuZ/fmmft6hifrF3Zt2KyA5EcJM9ejkRIk4pqmnozgKuHdYPBvy7xpA1syBIHHCWODxOblGX8U+FOAfNm7GA8bZ1Dd6EQIsqL/0uwAm1DKvas4TK9aCFl66D5uPa2Pa6jo72/9sFCbaHaJ6EaInWAbJ9IY+wKA=\\", \\"MODE\\": 2, \\"IV\\": \\"oUlQKjyfV+jP1pmy3/6e4A==\\", \\"ALG\\": 0}", "digest": "353cc4ae432f24f58700cc0336585af124495cc52252e339912d13cb5ee2b6c4", "alg": "HMAC_SHA2"}"""]

        messageList = [{"ker": {"__class__": "pairing.Element", "__value__": "1:D5M+tqPsvfQ2cv1Yt+JRDBtB7OPTndE+/F7hZp0Orrc+3to+Z0HJ4evG+/exABD46qUaVNmITGW4xbvk4YHFZwE=", "__pairingCurve__": "SS512"}, "nr": {"__class__": "bytes", "__value__": "kTTKZNUMXEay/CJ/mq0kuazryJG/AN/SX0nEOP4OG2g="}},
                       {"ker": {"__class__": "pairing.Element", "__value__": "1:D5M+tqPsvfQ2cv1Yt+JRDBtB7OPTndE+/F7hZp0Orrc+3to+Z0HJ4evG+/exABD46qUaVNmITGW4xbvk4YHFZwE=", "__pairingCurve__": "SS512"}, "nr": {"__class__": "bytes", "__value__": "kTTKZNUMXEay/CJ/mq0kuazryJG/AN/SX0nEOP4OG2g="}, 'dummy': 'blablabla'},
                       {"ker": {"__class__": "pairing.Element", "__value__": "1:D5M+tqPsvfQ2cv1Yt+JRDBtB7OPTndE+/F7hZp0Orrc+3to+Z0HJ4evG+/exABD46qUaVNmITGW4xbvk4YHFZwE=", "__pairingCurve__": "SS512"}, "nr": {"__class__": "bytes", "__value__": "kTTKZNUMXEay/CJ/mq0kuazryJG/AN/SX0nEOP4OG2g="}, 'dummy': 'blablablablablablabla'},
                       {"ker": {"__class__": "pairing.Element", "__value__": "1:D5M+tqPsvfQ2cv1Yt+JRDBtB7OPTndE+/F7hZp0Orrc+3to+Z0HJ4evG+/exABD46qUaVNmITGW4xbvk4YHFZwE=", "__pairingCurve__": "SS512"}, "nr": {"__class__": "bytes", "__value__": "kTTKZNUMXEay/CJ/mq0kuazryJG/AN/SX0nEOP4OG2g="}, 'dummy': 'blablablablablablablablablablablablabla'},
                       {'1': 1234453828282, 'first':'dummy string', "10": 828283882, 'another_dummy_string': 'more dummy strings'},
                       {'1': 1234453828282, 'first':'dummy string', "10": 828283882, 'another_dummy_string': 'more dummy strings', "500": 'useless string', "510": {'innerdict':10}, "550": 'spock'}]
        key = b'\x43' * 256

        for i in range(len(messageList)):
            # We are copying the function code here to shortcut the Mocking system. We have the byte message in the encryptedMessageList, but
            # we must first deserialize into a dictionary.
            encryptedPayloadWithHeaderBytes = encryptedMessageList[i]
            # Fetch the payload only in bytes.
            payloadBytes = locationserviceutility.extractPayloadFromRawMessage(encryptedPayloadWithHeaderBytes)
            # Deserialize the payload and insert the raw message into the dictionary. We now have the correct return of the receiveMessage function.
            payload = json.loads(payloadBytes.decode())
            payload.update({constants.PAYLOAD_FIELD_NAME_RAW_MESSAGE: encryptedPayloadWithHeaderBytes})
            print("encrypted payload dict:\n")
            print(payload, "\n")

            cipher = charm.toolbox.symcrypto.AuthenticatedCryptoAbstraction(key)
            # Fetch the header from the raw message within the structure.
            header = locationserviceutility.extractHeaderFromRawMessage(payload[constants.PAYLOAD_FIELD_NAME_RAW_MESSAGE])
            print("\n\nheader:\n", header)
            print("\npayload deserialized:\n", payload)

            try:
                decryptedPayload = cipher.decrypt(payload, header)
            except ValueError:
                print("MAC verification failed.")
                raise ValueError("locationserviceutility: receiveEncryptedMessage: MAC verification failed.")

            print("receiveEncryptedMessage: Receiving message:\n", decryptedPayload)
            # The decrypted message has only the original dictionary that would compose the plaintext message, without any raw message key:value.
            # Deserialize the decrypted message into the dictionary for comparison. The return of receiveEncryptedPayload should be a dictionary
            # without a rawMessage key, since we no longer need to calculate <SignedOctets> for encrypted messages. They are already
            # authenticated.
            decryptedPayloadDict = json.loads(decryptedPayload.decode())
            print("\n----Before assert ------\n")
            print("messageList:\n", messageList[i])
            print("\ndecryptedPayloadDict:\n", decryptedPayloadDict)
            self.assertEqual(decryptedPayloadDict, messageList[i])

    #@unittest.mock.patch('locationserviceutility.receiveMessage', autospec=True)
    def test_receiveEncryptedMessageMock(self):
        """
        Tests receiveEncryptedMessage function.
        """
        encryptedPayloadList = [{'header': {'counter': 0, 'spii': b'\x00\x00\x00\x00\x00\x00\x00\x10', 'exchange_type': b'a', 'length': 586, 'spir': b'Z\xfc\xdb\xc7pn\x7f\xf3', 'sender': False, 'message_type': False}, 'digest': 'cfd63ed9597517b5c02ad798206fbc9dae44cfb6add43cb4bff7b3a71d5a9ef3', 'rawMessage': b'\x00\x00\x02J\x00\x00\x00\x00\x00\x00\x00\x10Z\xfc\xdb\xc7pn\x7f\xf3\x00a\x00\x00\x00\x00\x00\x00{"msg": "{\\"CipherText\\": \\"czUsj2SjB09AnpIDbud9k95eWiMNExMcm+LnfdSkphUT6BKpMzfSSc71JNVBB20/xfPZKu2mma2f9Jn05OGT5bCOXJyKponwQbUlNHE4yBAeoVRzY+JaSafudHkO0ydg4+HK2mbHwblHTZ8SxP1jNTemFXgX++mW25gvhCBNOrhhV6CGe+QSX+nbrCEnhSs+1r+8wBP9XPn1PBnNHFbBA4BGKZo4ULSm3Ug9XiWd5/mHy/QpRKDE7W8YhXZSmXLXNYasMwI0CtxMvAnVcDmgcKHEb2ULdWTne6tqE5q6CZEU+xuT1ZAdxJMHipvk8oEaJLp7iI72pUFBuOpOeCs+QaF8LlMOnTAnpxk+64T5pNE=\\", \\"MODE\\": 2, \\"IV\\": \\"7Edv/L7AX1uYfSwyUzhsAQ==\\", \\"ALG\\": 0}", "digest": "cfd63ed9597517b5c02ad798206fbc9dae44cfb6add43cb4bff7b3a71d5a9ef3", "alg": "HMAC_SHA2"}', 'msg': '{"CipherText": "czUsj2SjB09AnpIDbud9k95eWiMNExMcm+LnfdSkphUT6BKpMzfSSc71JNVBB20/xfPZKu2mma2f9Jn05OGT5bCOXJyKponwQbUlNHE4yBAeoVRzY+JaSafudHkO0ydg4+HK2mbHwblHTZ8SxP1jNTemFXgX++mW25gvhCBNOrhhV6CGe+QSX+nbrCEnhSs+1r+8wBP9XPn1PBnNHFbBA4BGKZo4ULSm3Ug9XiWd5/mHy/QpRKDE7W8YhXZSmXLXNYasMwI0CtxMvAnVcDmgcKHEb2ULdWTne6tqE5q6CZEU+xuT1ZAdxJMHipvk8oEaJLp7iI72pUFBuOpOeCs+QaF8LlMOnTAnpxk+64T5pNE=", "MODE": 2, "IV": "7Edv/L7AX1uYfSwyUzhsAQ==", "ALG": 0}', 'alg': 'HMAC_SHA2'},
                                {'header': {'counter': 0, 'spii': b'\x00\x00\x00\x00\x00\x00\x00\x10', 'exchange_type': b'a', 'length': 630, 'spir': b'Z\xfc\xdb\xc7pn\x7f\xf3', 'sender': False, 'message_type': False}, 'digest': 'f116c46f134323ca0489c119eb6009f6629a247dcc2f7e9179460569ab8d1be9', 'rawMessage': b'\x00\x00\x02v\x00\x00\x00\x00\x00\x00\x00\x10Z\xfc\xdb\xc7pn\x7f\xf3\x00a\x00\x00\x00\x00\x00\x00{"msg": "{\\"CipherText\\": \\"qQWflGk6R7iXCaRunNDR78N8386mPOCaO28Tflk1+M7iKiFic6lDthwEc6e3Q14c7lIhAAZAXoAEjIVfyvdjYbwzrRByCOcKJWqUfeM0krZLSWA0zUaE84o3GykNLsZM4cYexMA5jG+jgtErjWfVU/rXgjN6EY6Aka8/iWUox+RBRut0J5a7KgAKKhX69miAru5IL9LwARRbQFskxY2OD1VKjxu3BoEcroYFH7Ndbt9DF7UUoS+R92+V2nm+9z4lWdXvrB1mZ7bC5Dh9/82HkOyYQVIQ8xgYOxRhRQ/N9Js5ThfCkkwjTIAfIiHypJEFdmmTZUNQ9K1nlnwE68NnOq36KwYlAS1Tz7TcKLgwBgQ6X3gSqF3Aq8+q6eHCaqtyKKx9j6Fuwi7EjFS8jGT9vg==\\", \\"MODE\\": 2, \\"IV\\": \\"rvz5ojbRFc4IQeQLMJoKPw==\\", \\"ALG\\": 0}", "digest": "f116c46f134323ca0489c119eb6009f6629a247dcc2f7e9179460569ab8d1be9", "alg": "HMAC_SHA2"}', 'msg': '{"CipherText": "qQWflGk6R7iXCaRunNDR78N8386mPOCaO28Tflk1+M7iKiFic6lDthwEc6e3Q14c7lIhAAZAXoAEjIVfyvdjYbwzrRByCOcKJWqUfeM0krZLSWA0zUaE84o3GykNLsZM4cYexMA5jG+jgtErjWfVU/rXgjN6EY6Aka8/iWUox+RBRut0J5a7KgAKKhX69miAru5IL9LwARRbQFskxY2OD1VKjxu3BoEcroYFH7Ndbt9DF7UUoS+R92+V2nm+9z4lWdXvrB1mZ7bC5Dh9/82HkOyYQVIQ8xgYOxRhRQ/N9Js5ThfCkkwjTIAfIiHypJEFdmmTZUNQ9K1nlnwE68NnOq36KwYlAS1Tz7TcKLgwBgQ6X3gSqF3Aq8+q6eHCaqtyKKx9j6Fuwi7EjFS8jGT9vg==", "MODE": 2, "IV": "rvz5ojbRFc4IQeQLMJoKPw==", "ALG": 0}', 'alg': 'HMAC_SHA2'},
                                {'header': {'counter': 0, 'spii': b'\x00\x00\x00\x00\x00\x00\x00\x10', 'exchange_type': b'a', 'length': 630, 'spir': b'Z\xfc\xdb\xc7pn\x7f\xf3', 'sender': False, 'message_type': False}, 'digest': 'b8301abcaa1babee7dd8d4edd9577b55fad74e303076227aded2df1b306dc43f', 'rawMessage': b'\x00\x00\x02v\x00\x00\x00\x00\x00\x00\x00\x10Z\xfc\xdb\xc7pn\x7f\xf3\x00a\x00\x00\x00\x00\x00\x00{"msg": "{\\"CipherText\\": \\"tP8va3uvC8H5OMCB4EGTl2kIk/SXsr8f6LmPfdN6r/S56crcs22Z/BaGG8ULh3iboGFdpUIU8+TT2BKDD88SFQUjqu2taZ2xyWxS9lxrOlkgMvaecuUbT5ZRwaE/bh0lM3uHZXXgVBVYTXjUXoZreXnKEEPi0Yf/750yuQwhMnILVNMfk/5Z21vZAHwAroFB2KFXca6lNlu/f96vpBT2Vs25gB/iTbX62eyKDKHLgQVIDpRJ+VcTsHZEUkODCImL6B5zuPy1bF2UFtd1V7Zq/tHDg0wW89oDgDIzJyHwAl+emytMNfOdgV1sFPCZU4e5Z4ZPb3MW7wmZMsXLdqbBXdTnFS+ti6OCI+ZIO+j+87Pi3NQ4jmWzfCwbsnMgpCggCiPB7M6JEHDsj63rcpHG9A==\\", \\"MODE\\": 2, \\"IV\\": \\"ZN+KvI47hg/6BjnWeXD66w==\\", \\"ALG\\": 0}", "digest": "b8301abcaa1babee7dd8d4edd9577b55fad74e303076227aded2df1b306dc43f", "alg": "HMAC_SHA2"}', 'msg': '{"CipherText": "tP8va3uvC8H5OMCB4EGTl2kIk/SXsr8f6LmPfdN6r/S56crcs22Z/BaGG8ULh3iboGFdpUIU8+TT2BKDD88SFQUjqu2taZ2xyWxS9lxrOlkgMvaecuUbT5ZRwaE/bh0lM3uHZXXgVBVYTXjUXoZreXnKEEPi0Yf/750yuQwhMnILVNMfk/5Z21vZAHwAroFB2KFXca6lNlu/f96vpBT2Vs25gB/iTbX62eyKDKHLgQVIDpRJ+VcTsHZEUkODCImL6B5zuPy1bF2UFtd1V7Zq/tHDg0wW89oDgDIzJyHwAl+emytMNfOdgV1sFPCZU4e5Z4ZPb3MW7wmZMsXLdqbBXdTnFS+ti6OCI+ZIO+j+87Pi3NQ4jmWzfCwbsnMgpCggCiPB7M6JEHDsj63rcpHG9A==", "MODE": 2, "IV": "ZN+KvI47hg/6BjnWeXD66w==", "ALG": 0}', 'alg': 'HMAC_SHA2'},
                                {'header': {'counter': 0, 'spii': b'\x00\x00\x00\x00\x00\x00\x00\x10', 'exchange_type': b'a', 'length': 670, 'spir': b'Z\xfc\xdb\xc7pn\x7f\xf3', 'sender': False, 'message_type': False}, 'digest': 'aadac9188ece35d9c175ebb4c05d20e3147197e16fd02d5c3976939c84236835', 'rawMessage': b'\x00\x00\x02\x9e\x00\x00\x00\x00\x00\x00\x00\x10Z\xfc\xdb\xc7pn\x7f\xf3\x00a\x00\x00\x00\x00\x00\x00{"msg": "{\\"CipherText\\": \\"SKHzjAqooeW2p3UDDRnOW1Z5CJ+oOVd7BGy4dX8P23wTZ7IeqDIVaGcDkibYQ5zKrrGSn0S/c1XhEUpCPykK1u1XxYMyJWvD6iw3I587/LY7sTQzTA1X3aRvQCCnZywZQxAcdW/ySGvduGMz3PQd6qpn4rJg4xFRznvcFhtC6yTqn9Vg+KWdi8XeivT3gAd3gnbcaUiQcp6C5xWWel8diaUJcA64RfhVUCNSYegrqTCtUAHr51eG6tZbFJ4il1WGqYjxj/Uk+mpYMCBlT8tlXgoRXfOT9M+CoX8ay/x3JTULtlAmNztCRNu5u/T7r1zGleb6Ge5H3i4Umz45/Zu35TiMVf1ha2Go1feak+7TYx+eGoAcv/4uOJ72xM6ldtAHTB4MqXUodS1kFQftBA/CBNnWs0W/GAY7hUCwEuSPANZqBT1BDbb11iBxSJXuj7dv\\", \\"MODE\\": 2, \\"IV\\": \\"jusieD2ld+ZSdKHNWdSfUA==\\", \\"ALG\\": 0}", "digest": "aadac9188ece35d9c175ebb4c05d20e3147197e16fd02d5c3976939c84236835", "alg": "HMAC_SHA2"}', 'msg': '{"CipherText": "SKHzjAqooeW2p3UDDRnOW1Z5CJ+oOVd7BGy4dX8P23wTZ7IeqDIVaGcDkibYQ5zKrrGSn0S/c1XhEUpCPykK1u1XxYMyJWvD6iw3I587/LY7sTQzTA1X3aRvQCCnZywZQxAcdW/ySGvduGMz3PQd6qpn4rJg4xFRznvcFhtC6yTqn9Vg+KWdi8XeivT3gAd3gnbcaUiQcp6C5xWWel8diaUJcA64RfhVUCNSYegrqTCtUAHr51eG6tZbFJ4il1WGqYjxj/Uk+mpYMCBlT8tlXgoRXfOT9M+CoX8ay/x3JTULtlAmNztCRNu5u/T7r1zGleb6Ge5H3i4Umz45/Zu35TiMVf1ha2Go1feak+7TYx+eGoAcv/4uOJ72xM6ldtAHTB4MqXUodS1kFQftBA/CBNnWs0W/GAY7hUCwEuSPANZqBT1BDbb11iBxSJXuj7dv", "MODE": 2, "IV": "jusieD2ld+ZSdKHNWdSfUA==", "ALG": 0}', 'alg': 'HMAC_SHA2'},
                                {'header': {'counter': 0, 'spii': b'\x00\x00\x00\x00\x00\x00\x00\x10', 'exchange_type': b'a', 'length': 374, 'spir': b'Z\xfc\xdb\xc7pn\x7f\xf3', 'sender': False, 'message_type': False}, 'digest': '16bd36f98f32165135e8093fa1338f35c65c8b32c2956f5213fc5eb599d01c5e', 'rawMessage': b'\x00\x00\x01v\x00\x00\x00\x00\x00\x00\x00\x10Z\xfc\xdb\xc7pn\x7f\xf3\x00a\x00\x00\x00\x00\x00\x00{"msg": "{\\"CipherText\\": \\"AARhyiMV7KwKfwPB1kfHSZpOCF2IzMWGKbgjESKanJXBZM/c2VmMA9h+llCNXhFo0HvIpcrxaxZfgqIS641txB2krAhbl9Lndw0p19WNAjwQpXUYNUiJYHCxSuLEB2OYIo3lRpptaNLmhtZSfDrJsw==\\", \\"MODE\\": 2, \\"IV\\": \\"pfSFGGcgSkGW9sv1jbkYJQ==\\", \\"ALG\\": 0}", "digest": "16bd36f98f32165135e8093fa1338f35c65c8b32c2956f5213fc5eb599d01c5e", "alg": "HMAC_SHA2"}', 'msg': '{"CipherText": "AARhyiMV7KwKfwPB1kfHSZpOCF2IzMWGKbgjESKanJXBZM/c2VmMA9h+llCNXhFo0HvIpcrxaxZfgqIS641txB2krAhbl9Lndw0p19WNAjwQpXUYNUiJYHCxSuLEB2OYIo3lRpptaNLmhtZSfDrJsw==", "MODE": 2, "IV": "pfSFGGcgSkGW9sv1jbkYJQ==", "ALG": 0}', 'alg': 'HMAC_SHA2'},
                                {'header': {'counter': 0, 'spii': b'\x00\x00\x00\x00\x00\x00\x00\x10', 'exchange_type': b'a', 'length': 458, 'spir': b'Z\xfc\xdb\xc7pn\x7f\xf3', 'sender': False, 'message_type': False}, 'digest': '353cc4ae432f24f58700cc0336585af124495cc52252e339912d13cb5ee2b6c4', 'rawMessage': b'\x00\x00\x01\xca\x00\x00\x00\x00\x00\x00\x00\x10Z\xfc\xdb\xc7pn\x7f\xf3\x00a\x00\x00\x00\x00\x00\x00{"msg": "{\\"CipherText\\": \\"kPKCqh9sQjnp3ssBahxC4oT3Yd+dqS48TN5mmQ8BB2iTnjnGEpQsEucv1DcunBMnHLMKef2b4eS4CFuZ/fmmft6hifrF3Zt2KyA5EcJM9ejkRIk4pqmnozgKuHdYPBvy7xpA1syBIHHCWODxOblGX8U+FOAfNm7GA8bZ1Dd6EQIsqL/0uwAm1DKvas4TK9aCFl66D5uPa2Pa6jo72/9sFCbaHaJ6EaInWAbJ9IY+wKA=\\", \\"MODE\\": 2, \\"IV\\": \\"oUlQKjyfV+jP1pmy3/6e4A==\\", \\"ALG\\": 0}", "digest": "353cc4ae432f24f58700cc0336585af124495cc52252e339912d13cb5ee2b6c4", "alg": "HMAC_SHA2"}', 'msg': '{"CipherText": "kPKCqh9sQjnp3ssBahxC4oT3Yd+dqS48TN5mmQ8BB2iTnjnGEpQsEucv1DcunBMnHLMKef2b4eS4CFuZ/fmmft6hifrF3Zt2KyA5EcJM9ejkRIk4pqmnozgKuHdYPBvy7xpA1syBIHHCWODxOblGX8U+FOAfNm7GA8bZ1Dd6EQIsqL/0uwAm1DKvas4TK9aCFl66D5uPa2Pa6jo72/9sFCbaHaJ6EaInWAbJ9IY+wKA=", "MODE": 2, "IV": "oUlQKjyfV+jP1pmy3/6e4A==", "ALG": 0}', 'alg': 'HMAC_SHA2'}]

        messageList = [{'header': {'counter': 0, 'spii': b'\x00\x00\x00\x00\x00\x00\x00\x10', 'exchange_type': b'a', 'length': 586, 'spir': b'Z\xfc\xdb\xc7pn\x7f\xf3', 'sender': False, 'message_type': False}, "ker": {"__class__": "pairing.Element", "__value__": "1:D5M+tqPsvfQ2cv1Yt+JRDBtB7OPTndE+/F7hZp0Orrc+3to+Z0HJ4evG+/exABD46qUaVNmITGW4xbvk4YHFZwE=", "__pairingCurve__": "SS512"}, "nr": {"__class__": "bytes", "__value__": "kTTKZNUMXEay/CJ/mq0kuazryJG/AN/SX0nEOP4OG2g="}},
                       {'header': {'counter': 0, 'spii': b'\x00\x00\x00\x00\x00\x00\x00\x10', 'exchange_type': b'a', 'length': 630, 'spir': b'Z\xfc\xdb\xc7pn\x7f\xf3', 'sender': False, 'message_type': False}, "ker": {"__class__": "pairing.Element", "__value__": "1:D5M+tqPsvfQ2cv1Yt+JRDBtB7OPTndE+/F7hZp0Orrc+3to+Z0HJ4evG+/exABD46qUaVNmITGW4xbvk4YHFZwE=", "__pairingCurve__": "SS512"}, "nr": {"__class__": "bytes", "__value__": "kTTKZNUMXEay/CJ/mq0kuazryJG/AN/SX0nEOP4OG2g="}, 'dummy': 'blablabla'},
                       {'header': {'counter': 0, 'spii': b'\x00\x00\x00\x00\x00\x00\x00\x10', 'exchange_type': b'a', 'length': 630, 'spir': b'Z\xfc\xdb\xc7pn\x7f\xf3', 'sender': False, 'message_type': False}, "ker": {"__class__": "pairing.Element", "__value__": "1:D5M+tqPsvfQ2cv1Yt+JRDBtB7OPTndE+/F7hZp0Orrc+3to+Z0HJ4evG+/exABD46qUaVNmITGW4xbvk4YHFZwE=", "__pairingCurve__": "SS512"}, "nr": {"__class__": "bytes", "__value__": "kTTKZNUMXEay/CJ/mq0kuazryJG/AN/SX0nEOP4OG2g="}, 'dummy': 'blablablablablablabla'},
                       {'header': {'counter': 0, 'spii': b'\x00\x00\x00\x00\x00\x00\x00\x10', 'exchange_type': b'a', 'length': 670, 'spir': b'Z\xfc\xdb\xc7pn\x7f\xf3', 'sender': False, 'message_type': False}, "ker": {"__class__": "pairing.Element", "__value__": "1:D5M+tqPsvfQ2cv1Yt+JRDBtB7OPTndE+/F7hZp0Orrc+3to+Z0HJ4evG+/exABD46qUaVNmITGW4xbvk4YHFZwE=", "__pairingCurve__": "SS512"}, "nr": {"__class__": "bytes", "__value__": "kTTKZNUMXEay/CJ/mq0kuazryJG/AN/SX0nEOP4OG2g="}, 'dummy': 'blablablablablablablablablablablablabla'},
                       {'header': {'counter': 0, 'spii': b'\x00\x00\x00\x00\x00\x00\x00\x10', 'exchange_type': b'a', 'length': 374, 'spir': b'Z\xfc\xdb\xc7pn\x7f\xf3', 'sender': False, 'message_type': False}, '1': 1234453828282, 'first':'dummy string', "10": 828283882, 'another_dummy_string': 'more dummy strings'},
                       {'header': {'counter': 0, 'spii': b'\x00\x00\x00\x00\x00\x00\x00\x10', 'exchange_type': b'a', 'length': 458, 'spir': b'Z\xfc\xdb\xc7pn\x7f\xf3', 'sender': False, 'message_type': False}, '1': 1234453828282, 'first':'dummy string', "10": 828283882, 'another_dummy_string': 'more dummy strings', "500": 'useless string', "510": {'innerdict':10}, "550": 'spock'}]
        key = b'\x43' * 256
        #targetList = []
        for i in range(len(encryptedPayloadList)):
            self.mock_locationserviceutility.return_value = encryptedPayloadList[i]
#            element = json.loads(json.dumps(messageList[i], cls=jsonhelper.KeyEncoder), cls=jsonhelper.KeyDecoder)
#            element.update({constants.HEADER_FIELD_NAME: encryptedPayloadList[i][constants.HEADER_FIELD_NAME]})
#            targetList.append(element)
#            print("json deserialized messageList {}, ".format(i), json.loads(json.dumps(messageList[i], cls=jsonhelper.KeyEncoder), cls=jsonhelper.KeyDecoder))
            decryptedPayload = locationserviceutility.receiveEncryptedMessage(len, key)
#            print("\n\ndecrypted payload: \n", decryptedPayload)
            # Strip the raw message before comparing the dicts.
            decryptedPayload.pop(constants.PAYLOAD_FIELD_NAME_RAW_MESSAGE)
            # To compare, we must completely deserialize the element in messageList. We cannot write deserialized pairing.Element values, only
            # the byte representation of them such as it is in messageList.
            # Since each element in messageList is already a dictionary, we first JSON serialize (which just converts the element into a str),
            # and then JSON deserialize it to convert back to dict will all levels deserialized.
            self.assertEqual(decryptedPayload, json.loads(json.dumps(messageList[i], cls=jsonhelper.KeyEncoder), cls=jsonhelper.KeyDecoder))

        #print("Complete list:\n", targetList)

    def test_isEntityIDvalid(self):
        """
        Tests the function that verifies whethern an entityID exists in the entity table of database.
        """
        # Fetch a list of existing entityIDs such that we can verify ones that truly exist first.
        con = sqlite3.connect(self.databaseLocationService)
        existingEntityID = con.execute("select entityID from entity").fetchall()
        # Assert the existence of the first one element.
        self.assertTrue(locationserviceutility.isEntityIDvalid(existingEntityID[0][0], database=self.databaseLocationService))
        # Now use some random entityID and assert it does not exist.
        randomEntityID = 'alsk13i8sa8-0923'
        self.assertFalse(locationserviceutility.isEntityIDvalid(randomEntityID, database=self.databaseLocationService))


    def tearDown(self):
        pass

if __name__ == '__main__':
    unittest.main(verbosity=2)
