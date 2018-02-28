# -*- coding: utf-8 -*-
"""
Created on Thu Jul 16 16:36:02 2015

@author: locksmith
"""

#import base64
import Crypto.Random
import Crypto.Hash.SHA256
#import onetimepass
import logging
import os.path
import OpenSSL
import socket
import Crypto.Hash
import Crypto.Protocol.KDF
#import sqlite3
import time
#import charm.adapters.dabenc_adapt_hybrid
import constants
import locationserviceutility
import abeauthorityagent
import json
import jsonhelper

class LocationService(object):
    """
    This class performs protocol operations related to the Location Service side,
    typically as responder.

    Registration needs:
        _ Location Service X.509 (public key or certificate).
        _ User's ABE attributes.
        _ User's password.
        _ User's ABE public/secret keys.
        _ User's TOTP secret key.
        _ Expiration time for secret keys/passwords.
    """
#    _LOGFILE = "locationservice.log"
#    _CERTFILE = "locationService.crt"
#    _KEYFILE = "locationService.key"
#    _DATABASE = "locationservice.db"

    def __init__(self, certFile=constants.LOCATION_SERVICE_CERTFILE,
                 keyFile=constants.LOCATION_SERVICE_KEYFILE,
                 database=constants.LOCATION_SERVICE_DATABASE):
        """
        Initialize the object.

        Some default parameters can be set here.

        certFile: filename for the X.509 certificate.
        keyFile: filename for the service's secret key.
        database: filename for the service's database.
        """
        # Set filename and logging level for log messages, and output formats.
        FORMAT = "%(asctime)s;%(levelname)s;%(message)s"
        DATEFORMAT = '%Y-%m-%d %H:%M:%S'
        #self.LOGFILE = logFile
        self.certFile = certFile
        self.keyFile = keyFile
        self.database = database
        #logging.basicConfig(filename=self.LOGFILE, level=logging.DEBUG, format=FORMAT, datefmt=DATEFORMAT)
        formatter = logging.Formatter(fmt=FORMAT, datefmt=DATEFORMAT)
        self.log = logging.getLogger(__name__)
        handler = logging.FileHandler(__name__+'.log')
        self.log.setLevel(logging.DEBUG)
        handler.setFormatter(formatter)
        self.log.addHandler(handler)
        # Log values of arguments.
        self.log.info("PKI certificate filename set: %s", self.certFile)
        self.log.info("PKI secret key filename set: %s", self.keyFile)
        self.log.info("Database filename set: %s", self.database)
        # Populate the Location Service X.509 certificate and private key from local files or by creating them if the files do not exist.
        self.x509, self.privateKey = self.createSelfSignedCertificate()
        self.log.info("Loaded X.509 and private key.")
        self.entityID = constants.ENTITY_ID_LOCATION_SERVICE
        # Create or get the Location Service's ABE keys by instantiating an abeauthority object for Location Service.
        self.locationServiceAuthorityObject = abeauthorityagent.ABEAuthority(self.entityID, database=self.database)
        self.locationServiceABEsecretKeys, self.locationServiceABEpublicKeys = self.locationServiceAuthorityObject.getOrCreateABEAuthorityKeys(attributes=[],
                                                                                                                                               expirationEpoch=constants.DEFAULT_ABE_AUTHORITY_KEY_EXPIRATION_SECONDS,
                                                                                                                                               database=self.database)

    def sign(self, message, digest='sha256'):
        """
        Signs a message using Location Service's private key.

        message: byte string message to be signed. It will be encoded in bytes.
        digest: digest/hash algorithm to generate digest of message, which then will be signed.

        Return: X.509 Signature as a byte object.
        """
        return OpenSSL.crypto.sign(self.privateKey, message, digest)

    def verify(self, message, signature, digest=constants.DIGEST_DEFAULT):
        """
        Verifies the signature of a message using the Location Service certificate.

        Not sure whether this function is really necessary here, since verification of signature is used by the client who
        receives the X.509 certificate, not by the "owner" of the certificate. But let's leave this function here.
        Note that the certificate is not passed as argument, as it normally would.

        message: byte string message whose signature is to be verified.

        Return: True if signature verifies, False if signature does not verify.
        """
        try:
            OpenSSL.crypto.verify(self.x509, signature, message, digest) # Will raise OpenSSL.crypto.Error if does not verify.
            return True
        except OpenSSL.crypto.Error:
            return False # Did not verify.

    def createSelfSignedCertificate(self, rsaKeyLength=constants.RSA_KEY_LENGTH, expireAfterSeconds=constants.DEFAULT_KEY_EXPIRATION_SECONDS,
                                    certFile=None, keyFile=None, digest=constants.DIGEST_DEFAULT):
        """
        Creates and returns a self-signed certificate for Location Service and the corresponding private key,
        or utilizes the ones stored at the local directory if exists. Notice that no CSR (Certificate Signing Request) is utilized.

        rsaKeyLength: RSA key length in bits, default=3072.
        expireAfterSeconds: Seconds after current time for expiration of the certificate, default is 10 years in seconds.
        certFile: Filename of the certificate file in PEM format, default is "locationService.crt"
        keyFile: Filename of the private key file in PEM format, default is "locationService.key"
        digest: digest/hash algorithm to sign the certificate, default is 'sha256'.

        Return:
        OpenSSL.crypto.X509 object certificate, OpenSSL.crypto.PKey object private key.
        """

        # Set certFile and keyFile.
        if certFile is None:
            certFile = self.certFile
        if keyFile is None:
            keyFile = self.keyFile
        # If the files are not here, then just create the certificate, private key, and save to the files.
        if not os.path.exists(certFile) or not os.path.exists(keyFile):

            # create a key pair
            pkey = OpenSSL.crypto.PKey()
            pkey.generate_key(OpenSSL.crypto.TYPE_RSA, rsaKeyLength)

            # create a self-signed cert
            cert = OpenSSL.crypto.X509()
            cert.get_subject().C = "US"
            cert.get_subject().ST = "Delaware"
            cert.get_subject().L = "Newark"
            cert.get_subject().O = "PristineTechLocker"
            cert.get_subject().OU = "PristineTechLocker"
            cert.get_subject().CN = socket.gethostname()
            cert.set_serial_number(888)
            # Get the current time and establish the expiration date 'days' after the current time.
            cert.gmtime_adj_notBefore(0) # Set generation time as now.
            cert.gmtime_adj_notAfter(expireAfterSeconds) # 10 years of validity by default.
            cert.set_issuer(cert.get_subject())
            cert.set_pubkey(pkey)
            cert.sign(pkey, digest)
            #print(cert)

            with open(certFile, "wt") as cert_file, open(keyFile, "wt") as key_file, open(certFile + ".txt", "wt") as cert_file_txt:
                self.log.info("X.509 or private key files not found. New ones will be created.")
                cert_file.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert).decode())
                self.log.info("X.509 file %s created.", certFile)
                key_file.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey).decode())
                self.log.info("Private key file %s created.", keyFile)
                cert_file_txt.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_TEXT, cert).decode())
                self.log.info("X.509 (text type) file %s created", certFile + ".txt")

        # If the files exist, then retrieve their data into the certificate and Pkey.
        else:
            with open(certFile, "rt") as cert_file, open(keyFile, "rt") as key_file:
                cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_file.read())
                self.log.info("X.509 certificate loaded from existing file %s", certFile)
                pkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key_file.read())
                self.log.info("Private key loaded from existing file %s.", keyFile)

        # Returns X.509 certificate (X509 object), private key (PKey object).
        return cert, pkey

    def generatePasswordHashPBKDF2(self, password, salt, dkLength=constants.PBKDF2_HASH_LENGTH_BYTES, count=constants.PBKDF2_COUNT, digestmodule=Crypto.Hash.SHA256):
        """
        Generates hashes from text passwords using PBKDF2 (PKCS#5 standard v2.0). The MAC module will be an HMAC, utilizing
        digestmodule as its hash function.

        password: password as string.
        salt: salt as byte string. Recommended, as RFC 2898, is a salt of length 64 bits (8 bytes).
        dkLength: length of the generated hash in bytes.
        count: number of passes for the KDF. Default is 4,096.
        digestmodule: the digest module or hash function to be utilized within the HMAC. Default is Crypto.Hash.SHA256.

        Return:
        hash of password as byte string, of dkLength size in bytes.
        """

        return Crypto.Protocol.KDF.PBKDF2(password, salt, dkLen=dkLength, count=count,
                                          prf=lambda p,s: Crypto.Hash.HMAC.new(p,s,digestmodule).digest())

#==============================================================================
#     def registerKeyToDatabase(self, entityID, key, salt, keyTypeFk, algorithm,
#                               creationEpoch=None, expirationEpoch=None, lastUsedEpoch=None, database=None):
#         """
#         Registers a password hash or secret key for a specific entityID to the Location Service database, including the given salt used to compute the hash,
#         the hash function algorithm, and the time of utilization. If there is an entry with the same entityID, key, sal, algorithm, keyType,
#         the function returns False, otherwise returns True.
#
#         entityID: ID of the entity who owns the hash as string.
#         key: hash of the password to record to the database, as byte string.
#         salt: salt utilized to compute the password as byte string.
#         keyTypeFk: the type index of key recorded here (the table's foreign key). Types are defined within the database.
#         algorithm: hash function that computed the hash (the function within the HMAC), as string (e.g., 'PBKDF2-HMAC-SHA256').
#         creationEpoch: epoch when the key was registered to the database.
#         expirationEpoch: epoch of the expiration date of this key.
#         lastUsedEpoch: the epoch of the recording. Default is None, which will then utilize the current epoch. This is an epoch float.
#         database: filename of database. If None, default instance database will be utilized.
#
#         Return:
#         True if the registration was successful; False if a similar record (but for the lastTimeUsed) was found.
#
#         Note: Perhaps the function should update the lastTimeUsed if a similar record is found?
#         """
#
#         nowEpoch = time.time()
#         # Set database. lastTimeUsed will be set at the moment of recording.
#         if database is None:
#             database = self.database
#
#         # Verify whether same entry already exists in database.
#         con = sqlite3.connect(database)
#         with con:
#             # TODO: something must be done here regarding expirationEpoch! If the key is expired, can we insert the same one with new expiration date?
#             result = con.execute("""select * from entityKey where """
#                                  """entityFk=(select primaryKey from entity where entityID=?) and """
#                                  """key=? and salt=? and keyTypeFk=? and algorithm=? and """
#                                  """expirationEpoch > ?""",
#                                  (entityID, key, salt, keyTypeFk, algorithm, nowEpoch)).fetchall() # The expirationEpoch > time.time() here will fetch non-expired entries.
#             # If something was found, then record already exists and it is still valid (expirationEpoch <= time.time()) for the key and salt. Return False.
#             if result:
#                 return False
#
#             # Record does not exist. Insert.
#             # Define creationEpoch and lastUsedEpoch to current time if values were not passed as arguments.
#             if creationEpoch is None:
#                 creationEpoch = nowEpoch
#             if lastUsedEpoch is None:
#                 lastUsedEpoch = nowEpoch
#             con.execute("""insert into entityKey(entityFk, key, salt, keyTypeFk, algorithm,"""
#                         """creationEpoch, expirationEpoch, lastUsedEpoch) values ("""
#                         """(select primaryKey from entity where entityID=?),?,?,?,?,?,?,?)""",
#                         (entityID, key, salt, keyTypeFk, algorithm, creationEpoch, expirationEpoch, lastUsedEpoch))
#             return True
#==============================================================================

    def generateTotpRandomSecret(self, length=constants.RANDOM_SECRET_LENGTH_BITS):
        """
        Generate a random, base32-encoded string of 'length' length.

        The random string, before encoding, contains uppercase and lowercase letters and digits.

        length: length of random string to generate, in bits, before base32 encoding. Default is 32 bytes or 256 bits.

        Return: base32-encoded string.
        """

        return locationserviceutility.generateTotpRandomSecret(length=length)

    def registerEntityAttribute(self, entityID, attribute,
                              creationEpoch=None, expirationEpoch=None, lastUpdatedEpoch=None, database=None):
        """
        Registers a entity attribute.
        Note that if the entity already has the attribute, then the expirationEpoch will be updated with the one
        passed as argument, regardless of whether the new occurs after or before the one in the database.

        entityID: ID of the entity who owns the hash as string.
        attribute: attribute string of the entity to be registered to the database. It must previously exist in attribute table.
        creationEpoch: epoch when the key was registered to the database.
        expirationEpoch: epoch of the expiration date of this key.
        lastUpdatedEpoch: epoch at which the attribute was last updated (basically, when the expirationEpoch was last altered).
        database: filename of database. If None, default instance database will be utilized.
        """

        nowEpoch = time.time()
        # Set database. lastTimeUsed will be set at the moment of recording.
        if database is None:
            database = self.database
        if creationEpoch is None:
            creationEpoch = nowEpoch
        if lastUpdatedEpoch is None:
            lastUpdatedEpoch = nowEpoch

        locationserviceutility.registerEntityAttribute(entityID, attribute, creationEpoch, expirationEpoch, lastUpdatedEpoch,
                                                       database)


    def getAllEntityAttributes(self, entityID, notExpiredBeforeEpoch=None, database=None):
        """
        Retrieves all entity attributes from database with expirationEpoch on or after notExpiredBeforeEpoch, i.e.,
        that are not expired before notExpiredBeforeEpoch.

        entityID: ID of the entity who owns the attributes.
        notExpiredBeforeEpoch: attributes will be retrieved if their expirationEpoch is equal or greater then
            notExpiredBeforeEpoch.
        database: filename of database. If None, default instance database will be utilized.

        Return:
        List of unique entity attributes, wherein each element is a string.
        """

        nowEpoch = time.time()
        # Set database.
        if database is None:
            database = self.database

        # If not specified, set notExpiredBeforeEpoch to this instant.
        if notExpiredBeforeEpoch is None:
            notExpiredBeforeEpoch = nowEpoch

        return locationserviceutility.getAllEntityAttributes(entityID, notExpiredBeforeEpoch, database)

    def getAllLikeAttributes(self, searchString, database=None):
        """
        Retrieves all attributes that match a certain search string.

        Typically, this function will be utilized to retrieve all attributes belonging to an authority, such
        as all attributes beginning with "amazon.*".

        searchString: search string or pattern to which the attributes in the database will be compared.
        database: name of the database file.

        Return:
        List of attributes, wherein each element is a string matching the searchString.
        """

        # Set database.
        if database is None:
            database = self.database

        return locationserviceutility.getAllLikeAttributes(searchString, database)
        
    def generateBnonce(self, authorityList, accessPolicy, length=constants.BNONCE_LENGTH_BITS, pairingGroup=constants.DEFAULT_PAIRING_GROUP):
        """
        Generates the BNONCE for LOCATHE protocol and signs it using Location Service's certificate.
        
        This function generates a nonce, which we assume it is a random, unique value of certain length. The nonce
        is encrypted with the access policy and using the ABE public keys of all authority entities in the authorityList.
        If the authorityList is empty, only the Location Service ABE public key is utilized.
        The function will fetch the appropriate ABE authority public keys from the database and feed them to the encryption
        algorithm.
        
        Parameters
        ----------
        authorityList : list of str, optional
            list of entityIDs of authorities. If empty, only Location Service entityID will be used.
        accessPolicy : str
            string containting the logical expression for the access policy with attributes.
            E.g., green AND electrical OR gas
        pairingGroup : str, optional
            Pairing group identificator.
            
        Returns
        -------
        byte str, str, byte str
            the random nonce Nb (for LOCATHE);
            the json-serialized encrypted nonce, the BNONCE, per the access policy and authority's ABE public keys;
            signature of serialized BNONCE using Location Service's certificate.
            
        Notes
        -----
        An alternative function would, instead of receiving an authorityList as argument, receive a list of ABE public keys
        or a big dictionary of public keys, and thus would not attempt to retrieve keys from the database. In this format,
        it would make sense that the Location Service would request the authority's public keys to generate bnonces. The
        problem is the communication overhead; caching the public keys to avoid requesting is similar to storing them into the database.
        """
        # First, gather all ABE public keys into a single dictionary.
        # If the list is empty, populate it with Location Service entityID.
        if not authorityList: # = []
            authorityList = constants.ENTITY_ID_LOCATION_SERVICE
        abePublicKeys = {}
        keyType = constants.ABE_AUTHORITY_PUBLIC_KEY_TYPE
        for entityID in authorityList:
            abePublicKeys.update(locationserviceutility.mergeListOfJsonObjectsIntoOneDictionaryAndDeserialize(locationserviceutility.getEntityKeysOfType(entityID, keyType, database=self.database)))        
        #print("Keys:")
        #print(abePublicKeys)
        # Generate the random nonce.
        nb = locationserviceutility.generateNonce(length=length)
        # Create the objects needed for ABE encryption.
        hybridAbeMultiAuthorityObject, globalParameter, groupObject = self.locationServiceAuthorityObject.createHybridABEMultiAuthorityObject(pairingGroup=pairingGroup)
        # Now encrypt the random nonce.
        # TODO: We are using Authenticated Encryption. Perhaps we should use non-authenticated encryption to avoid brute-force key guess attacks.
        bnonce = hybridAbeMultiAuthorityObject.encrypt(globalParameter, abePublicKeys, nb, accessPolicy)
        bnonceSerialized = json.dumps(bnonce, cls=jsonhelper.KeyEncoder, pairingCurve=groupObject.param)
        self.log.info("New BNONCE generated.")
        bnonceSignature = self.sign(bnonceSerialized)
        return nb, bnonceSerialized, bnonceSignature
        #return nb, bnonce, bnonceSignature
        
    def getCertificateAsString(self):
        """
        Gets the (PKI) certificate in string format.
        
        Returns
        -------
        str
            Certificate in string format (not byte string).
        """
        return OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, self.x509).decode()

#==============================================================================
#     def getKeyTypePk(self, keyType):
#         """
#         Return the keyType primary key per the key type description (string).
#
#         keyType: string with keyType description.
#
#         Return:
#         keyType primary key.
#         """
#         con = sqlite3.connect(self.database)
#         with con:
#             return con.execute("select primaryKey from keyType where keyType=?", (keyType,)).fetchone()[0]
#
#==============================================================================

