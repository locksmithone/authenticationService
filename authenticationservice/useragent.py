# -*- coding: utf-8 -*-
"""
Created on Thu Jul 16 17:15:41 2015

@author: locksmith
"""

import Crypto.Random
import onetimepass
from charm.schemes.abenc.dabe_aw11 import Dabe
from charm.toolbox.pairinggroup import PairingGroup
from charm.adapters.dabenc_adapt_hybrid import HybridABEncMA
import json
import jsonhelper
#import charm.core.math.pairing
import sqlite3
import logging
import time
import constants
import OpenSSL
import locationserviceutility
import os.path


class UserAgent(object):
    """
    This class performs protocol operations related to the User Agent side,
    typically as responder.

    Registration needs:
        _ Location Service X.509 (public key or certificate).
        _ User's ABE attributes.
        _ User's password.
        _ User's ABE public/secret keys.
        _ User's TOTP secret key.
        _ Expiration time for secret keys/passwords.

    A typical structure for the User record would be:
    User record {
        entityID
        Attributes
    }

    Password {
        	entityID
        	passwordHash
        	Salt
        	Algorithm
        	Status
        		[expired | valid]
        	lastUsedTime
        	*lastPasswordHashes
    }

    """

    def __init__(self, entityID, certFile=constants.LOCATION_SERVICE_CERTFILE, database=constants.LOCATION_SERVICE_USER_DATABASE):
        """
        Initialize the object.

        Some default parameters can be set here.

        Parameters
        ----------
        entityID : str
            ID of the entity (user) represented by this object.
        certFile : str
            filename for the X.509 certificate from the Location Service.
        database : str
            filename for the User Agent database.
        """
        # Set filename and logging level for log messages, and output formats.
        FORMAT = "%(asctime)s;%(levelname)s;%(message)s"
        DATEFORMAT = '%Y-%m-%d %H:%M:%S'
        formatter = logging.Formatter(fmt=FORMAT, datefmt=DATEFORMAT)
        self.log = logging.getLogger(__name__)
        handler = logging.FileHandler(__name__+'.log')
        self.log.setLevel(logging.DEBUG)
        handler.setFormatter(formatter)
        self.log.addHandler(handler)

        self.entityID = entityID
        self.certFile = certFile
        self.database = database
        self.x509 = self.readX509CertificateFromFile()

        # Log values of arguments.
        self.log.info("Database filename set: %s", self.database)
        # Set key filenames if key files are to be used.
        self.log.info("User Agent object instantiated.")

    def readX509CertificateFromFile(self, certFile=None):
        """
        Reads a X.509 certificate from a local crt file. If the file does not exist, returns None.

        Parameters
        ----------
        certFile : str
            Filename of the certificate file in PEM format, optional.

        Returns
        -------
        OpenSSL.crypto.X509 object certificate
            or None if the file does not exist.
        """

        # Set certFile and keyFile.
        if certFile is None:
            certFile = self.certFile
        # If the file is not here, then return None immediately.
        if not os.path.exists(certFile):
            return None
        # If the file exists, then retrieve the data into the certificate.
        else:
            with open(certFile, "rt") as cert_file:
                cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_file.read())
                self.log.info("X.509 certificate loaded from existing file %s", certFile)

        # Returns X.509 certificate (X509 object).
        return cert

    def verify(self, message, signature, digest=constants.DIGEST_DEFAULT):
        """
        Verifies the signature of a message using the Location Service certificate.

        Parameters
        ----------
        message : byte str
            message whose signature is to be verified.
        signature : byte str
            signature or MAC of the message for comparison.
        digest : str
            digest/hash algorithm to sign the certificate, default is 'sha256'.

        Returns
        -------
        bool
            True if signature verifies, False if signature does not verify.
        """
        try:
            OpenSSL.crypto.verify(self.x509, signature, message, digest) # Will raise OpenSSL.crypto.Error if does not verify.
            return True
        except OpenSSL.crypto.Error:
            return False # Did not verify.

    def createHybridABEMultiAuthorityObject(self, pairingGroup=constants.DEFAULT_PAIRING_GROUP):
        """
        Create a HybridABEncMA (dabenc_adapt_hybrid.py) object for use in instantiating a global parameter setup, encryption, decryption, etc.

        In particular, the global parameter setup will always utilize a global, constant random group generator, and to which a random oracle hash
        function.

        This function just calls the locationserviceutility version of it for compatibility.

        Parameters
        ----------
        pairingGroup : str, optional
            Pairing group identifier for the group object.

        Returns
        -------
        object, object, object
            HybridABEncMA object, globalParameter (from HybridABEncMA.setup method) object, PairingGroup object
        """
        return locationserviceutility.createHybridABEMultiAuthorityObject(pairingGroup=pairingGroup)


    def abeDecrypt(self, ciphertext, pairingGroup=constants.DEFAULT_PAIRING_GROUP):
        """
        Decrypts an ABE-encrypted ciphertext, using the ABE secret keys belonging to the user/entityID.
        For the decryption to work correctly with Charm Crypto, the function needs to re-insert the 'gid':entityID key/value,
        since the decryption algorithm will look for it and will return an error if not found.

        Parameters
        ----------
        ciphertext : dict
            The Charm-Crypto-style dict representing the ABE-encrypted ciphertext.

        Returns
        -------
        str
            the plaintext resulting from the decryption of the ciphertext, or None if decryption failed.
            Decryption may fail because the ciphertext's MAC is incorrect, or if the entity does not possess the proper ABE secret keys to decrypt.

        Notes
        -----
        In case of failed decryption, the caller must decide what to do. For instance, in the LOCATHE protocol, the user may opt to continue with the protocol
        and allow the authentication to fail later in the protocol due to an incorrect Nb. This behaviour would impose, for example, an extra time penalty to
        an attacker attempting to use the user agent as an online decryption oracle. If the user agent reports a failed BNONCE immediately, an attacker can then try
        feeding the user agent more choices of BNONCE.
        """
        # First, gather all ABE secret keys into a single dictionary.
        keyType = constants.ABE_USER_SECRET_KEY_TYPE
        abeSecretKeys = locationserviceutility.mergeListOfJsonObjectsIntoOneDictionaryAndDeserialize(locationserviceutility.getEntityKeysOfType(self.entityID, keyType, database=self.database))
        # Insert the 'gid':entityID key/value.
        abeSecretKeys.update({constants.CHARM_CRYPTO_DECENTRALIZED_ABE_GID_KEY:self.entityID})
        # Get the default global parameter.
        hybridAbeMultiAuthorityObject, globalParameter, groupObject = self.createHybridABEMultiAuthorityObject(pairingGroup=pairingGroup)
        # Attempt decryption. If it works, return the plaintext. Otherwise, return None. Do not allow the decryption to throw exceptions.
        try:
            plaintext = hybridAbeMultiAuthorityObject.decrypt(globalParameter, abeSecretKeys, ciphertext)
        except Exception:
            # Be careful with these log messages! If an attacker has access to the logs, in particular real-time, the attacker will know about the result of ABE decryption. Online decryption oracle.
            self.log.warning("ABE decryption failed.")
            return None
        else:
            self.log.info("ABE decryption successful.")
            return plaintext