# -*- coding: utf-8 -*-
"""
Created on Sat Dec 26 14:32:33 2015

@author: locksmith
"""

from charm.schemes.abenc.dabe_aw11 import Dabe
#from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
from charm.toolbox.pairinggroup import PairingGroup
from charm.adapters.dabenc_adapt_hybrid import HybridABEncMA
import json
import jsonhelper
#import charm.core.math.pairing
import sqlite3
import logging
import os.path
import time
import constants
import locationserviceutility

class ABEAuthority(object):
    """
    This class performs operations directly related to ABE authorities, such as key creation, manipulation.
    """
    def __init__(self, entityID, secretKeyFilename=None, publicKeyFilename=None, database=constants.LOCATION_SERVICE_AUTHORITY_DATABASE):
        """
        Initialize the object.

        Some default parameters can be set here.

        Parameters
        ----------
        entityID : str
            ID of the entity represented by this object.
        secretKeyFilename : str
            filename wherein the secret ABE keys are stored.
        publicKeyFilename : str
            filename wherein the public ABE keys are stored.
        database : str
            filename for the Relying Party/Authority database.
        """
        # Set filename and logging level for log messages, and output formats.
        FORMAT = "%(asctime)s;%(levelname)s;%(message)s"
        DATEFORMAT = '%Y-%m-%d %H:%M:%S'
        #self.LOGFILE = logFile
        #logging.basicConfig(filename=self.LOGFILE, level=logging.DEBUG, format=FORMAT, datefmt=DATEFORMAT)
        #logging.basicConfig(level=logging.DEBUG, format=FORMAT, datefmt=DATEFORMAT)
        formatter = logging.Formatter(fmt=FORMAT, datefmt=DATEFORMAT)
        self.log = logging.getLogger(__name__)
        handler = logging.FileHandler(__name__+'.log')
        self.log.setLevel(logging.DEBUG)
        handler.setFormatter(formatter)
        self.log.addHandler(handler)

        self.entityID = entityID
        self.database = database
        # Log values of arguments.
        self.log.info("Database filename set: %s", self.database)
        # Set key filenames if key files are to be used.
        self.secretKeyFilename = secretKeyFilename
        self.publicKeyFilename = publicKeyFilename
        self.log.info("ABE authority object instantiated.")
        self.log.info("ABE public key filename set: %s", self.publicKeyFilename)
        self.log.info("ABE secret key filename set: %s", self.secretKeyFilename)

        # Retrieve or create the authority's ABE secret and public keys.
        # XXX: 2016.09.06: Undecided about this feature. We might disable this auto-creation in the future.
        self.abeSecretKeys, self.abePublicKeys = self.getOrCreateABEAuthorityKeys(attributes=[],
                                                                                  expirationEpoch=time.time() + constants.DEFAULT_ABE_AUTHORITY_KEY_EXPIRATION_SECONDS,
                                                                                  database=self.database)
        #self.log.info("Database: %s", self.database)

    def createABEAuthorityKeysFile(self, attributes=[], pairingGroup=constants.DEFAULT_PAIRING_GROUP, creationEpoch=None, expirationEpoch=None):
        """
        Create new secret and public ABE keys for an authority, or read and return them from existing files.

        *This is a legacy function. Consider it deprecated for now.*

        Mimicking what OpenSSL does with PKI certificate and secret (private) key files, this function will create
        the public and secret keys for an ABE authority based on the authority's set of attributes. It will then
        save the keys to respective files. However, if the files already exist, then the function will ready the
        corresponding keys and return them into appropriate structures (typically Charm dictionaries).

        Note that the created keys need not necessarily belong to one authority. The function does not check for that:
        it assumes all passed attributes belong to the same authority. It will create the keys regardless of the name
        of the attribute. In real world, if one authority creates keys for another authority, it will result in a conflict
        and, typically, users will only trust the genuine authority from which to obtain their secret ABE user keys.

        One issue is what exactly to do when key creation is requested and there are existing keys into the files, but
        potentially not for all the desired attributes. Do we check each attribute to verify whether there are existing keys,
        and create keys for non-existing ones? Do we recreate all? Do we check for expiration time?

        Recreating the key pairs is a problem, because it will immediately invalidate keys already issued for users for new
        encryptions. If we recreate authority keys, we must issue new keys to users, and old encryptions will therefore fail
        will new keys and vice-versa.

        We may add a few extra data into the original Charm dictionary structures for the ABE public keys (mimicking
        PKI certificates), such as expiration, algorithms, identifiers. Secret key files in PKI contain nothing else
        than the key, so we will maintain the same style here. The extra data will have to apply to a set of keys/attributes,
        since the original charm data structure is a one-level dictionary, and thus we do not want to add another level to
        aggregate key/expiration/algorithm, etc.

        Parameters
        ----------
        attributes : list of str, optional (default is empty list)
            list of string attributes to which create keys.
        pairingGroup : str
            PairingGroup name with which ABE keys are to be created. Default is constants.DEFAULT_PAIRING_GROUP.
        creationEpoch : str
            epoch when the key was registered to the database. Will default to time.time() if not specified.
        expirationEpoch : str
            epoch of the expiration date of this key.

        Returns
        -------
        dict, dict
            Secret ABE keys for the authority.
            Public ABE keys for the authority.

        .. warning:: This proof-of-concept prefers the database for storage of ABE keys instead of files. Avoid this function.
        """

        nowEpoch = time.time()
        #database="locationservicetest.db"
        # If any of the public/secret key files are not here, then just create the public and secret keys, and save them to the files.
        # Having only one of the files does not suffice; there has to be a pair of files.
        if not os.path.exists(self.publicKeyFilename) or not os.path.exists(self.secretKeyFilename):
            self.log.info("Either ABE public/secret key filenames does not exist. Both will be recreated with new keys.")
            hybridDecentralizedABEObject, globalParameter, groupObject = self.createHybridABEMultiAuthorityObject(pairingGroup = pairingGroup)

            if creationEpoch is None:
                creationEpoch = nowEpoch
            # Now create the pair of ABE keys for each attribute. Each key set is a dictionary.
            (authoritySecretKeys, authorityPublicKeys) = hybridDecentralizedABEObject.authsetup(globalParameter, attributes)

#==============================================================================
#             # 2016.09.14: Let's disable this feature for now. The prorogue, expire functions do not really update the fields within
#             # the dictionaries, therefore the expirationEpoch becomes unmatched with the same field in the database.
#             # Put in additional information for future use, such as creation Epoch, expiration, type of pairing curve...
#
#             # Notice that the current information being added is per "group" of attribute keys, not per single attribute key.
#             # Put additional data (creationEpoch and expirationEpoch) in each attribute key.
#             for authoritySecretKeys_key in authoritySecretKeys:
#                 # Do this if the entry is an inner dictionary.
#                 if isinstance(authoritySecretKeys[authoritySecretKeys_key], dict):
#                     authoritySecretKeys[authoritySecretKeys_key].update({'__creationEpoch__':creationEpoch, '__expirationEpoch__':expirationEpoch})
#
#             for authorityPublicKeys_key in authorityPublicKeys:
#                 # Do this if the entry is an inner dictionary.
#                 if isinstance(authorityPublicKeys[authorityPublicKeys_key], dict):
#                     authorityPublicKeys[authorityPublicKeys_key].update({'__creationEpoch__':creationEpoch, '__expirationEpoch__':expirationEpoch})
#
#==============================================================================
            # Add the pairingCurve type to the whole key set.
            # 2016/08/21 MP: Let's not do this anymore. Allow the keys to be completely empty if no keys were created
            # (for example, for an empty list of attributes). Otherwise, even for empty keys, the elements
            # '__pairingCurve__' and etc. will still be added and will eventually be registered to the database, without any
            # valid keys.
            # Since jsonhelper.py does add the necessary fields for proper deserialization, we do not need the upper level pairing curve fields.
            #authoritySecretKeys.update({'__pairingCurve__':groupObj.param})
            #authorityPublicKeys.update({'__pairingCurve__':groupObj.param})

            # Now save the newly created keys to the files.
            with open(self.publicKeyFilename, "wt") as pkFilename, open(self.secretKeyFilename, "wt") as skFilename:
                pkFilename.write(json.dumps(authorityPublicKeys, cls=jsonhelper.KeyEncoder, pairingCurve=groupObject.param))
                self.log.info("ABE public key file %s created.", self.publicKeyFilename)
                skFilename.write(json.dumps(authoritySecretKeys, cls=jsonhelper.KeyEncoder, pairingCurve=groupObject.param))
                self.log.info("ABE secret key file %s created.", self.secretKeyFilename)
        # Files exist: read the current keys from them. Still not addressing key update (or substitution) here.
        else:
            #print(pairingGroup)
            self.log.info("Both ABE public and secret key files exist. Keys will be read from these files.")
            with open(self.publicKeyFilename, "rt") as pkFilename, open(self.secretKeyFilename, "rt") as skFilename:
                authorityPublicKeys = json.loads(pkFilename.read(), cls=jsonhelper.KeyDecoder)
                self.log.info("ABE public key file %s read into public keys.", self.publicKeyFilename)
                authoritySecretKeys = json.loads(skFilename.read(), cls=jsonhelper.KeyDecoder)
                self.log.info("ABE secret key file %s read into secret keys.", self.secretKeyFilename)

        return authoritySecretKeys, authorityPublicKeys

    def createHybridABEMultiAuthorityObject(self, pairingGroup=constants.DEFAULT_PAIRING_GROUP):
        """
        Create a HybridABEncMA (dabenc_adapt_hybrid.py) object for use in instantiating a global parameter setup, encryption, decryption, etc.

        In particular, the global parameter setup will always utilize a global, constant random group generator, and to which a random oracle hash
        function.
        
        This function just calls the locationserviceutility version of it for compatibility.

        Parameters
        ----------
        pairingGroup : str, optional

        Returns
        -------
        object, object, object
            HybridABEncMA object, globalParameter (from HybridABEncMA.setup method) object, PairingGroup object
        """
        return locationserviceutility.createHybridABEMultiAuthorityObject(pairingGroup=pairingGroup)


    def createABEAuthorityKeys(self, attributes=[], pairingGroup=constants.DEFAULT_PAIRING_GROUP, creationEpoch=None, expirationEpoch=None, database=None):
        """
        Create new secret and public ABE keys for an authority.

        Note: valid keys are considered those which expirationEpoch is greater than time.time().

        Note that the created keys need not necessarily belong to one authority. The function does not check for that:
        it assumes all passed attributes belong to the same authority. It will create the keys regardless of the name
        of the attribute. In real world, if one authority creates keys for another authority, it will result in a conflict
        and, typically, users will only trust the genuine authority from which to obtain their secret ABE user keys.

        One issue is what exactly to do when key creation is requested and there are existing keys into the files, but
        potentially not for all the desired attributes. Do we chee database has valid, existing keys, the function
        should cause an error (or return None?).ck each attribute to verify whether there are existing keys,
        and create keys for non-existing ones? Do we recreate all? Do we check for expiration time?

        Recreating the key pairs is a problem, because it will immediately invalidate keys already issued for users for new
        encryptions. If we recreate authority keys, we must issue new keys to users, and old encryptions will therefore fail
        will new keys and vice-versa.

        2016.08.19 modification: attributes parameter with default None, such that we may call this function without passing
        attributes. In this case, the function will retrieve all attributes belonging to the authority directly from
        database.

        Parameters
        ----------
        attributes : list of str, optional, default empty list
            list of string attributes to which create keys.
        pairingGroup : str, optional
            PairingGroup name with which ABE keys are to be created. Default is constants.DEFAULT_PAIRING_GROUP.
        creationEpoch : epoch, optional
            epoch when the key was registered to the database. Will default to time.time() if not specified.
        expirationEpoch : epoch, optional
            epoch of the expiration date of this key.
        database : str, optional
            filename of database. If None, default instance database will be utilized.

        Returns
        -------
        dict, dict
            Secret ABE keys for the authority.
            Public ABE keys for the authority.
            Or empty keys if there are existing, valid keys in the database, or if the keys were not created (possibly empty attributes).
        
        Notes
        -----
        2016.10.25: In the current implementation, expirationEpoch cannot be NULL in the database. Not passing its value
        as argument for this function will result in sqlite3 exception.
        """

        nowEpoch = time.time()
        # Set database.
        if database is None:
            database = self.database

        # First, check whether there are valid (non-expired) keys for the attributes. If there are, exit with error.
        # In this case, the user should first expire or delete the keys, and then create new ones.
        # Test here for any of ABE Secret Key, or ABE Public Key. If any component is still valid, it must be first expired
        # before attempting to create new ones (right?).
        # Note: valid keys are considered those which expirationEpoch is greater than time.time().
        con = sqlite3.connect(database)
        with con:
            result = con.execute("""select * from entityKey where """
                                 """entityFk=(select primaryKey from entity where entityID=?) and """
                                 """keyTypeFk in (select primaryKey from keyType where keyType=? or keyType=?) and """
                                 """expirationEpoch > ?""",
                                 (self.entityID, constants.ABE_AUTHORITY_SECRET_KEY_TYPE, constants.ABE_AUTHORITY_PUBLIC_KEY_TYPE, nowEpoch)).fetchall() # The expirationEpoch > time.time() here will fetch non-expired entries.
        # If something was found, then record already exists and it is still valid (expirationEpoch <= time.time()) for the key and salt. Return False.
        if result:
            # Exit immediately after logging error.
            self.log.error("There are still valid (non-expired) ABE public or secret keys. Cannot create new keys in this situation.")
            #raise SystemExit("There are still valid (non-expired) ABE public or secret keys. Cannot create new keys in this situation.")
            return {}, {}

        # Else, create the public and secret keys for the authority, per attributes, and store them into database.
        self.log.info("Either ABE public/secret key entries in the database do not exist. Both will be recreated with new keys.")
        hybridDecentralizedABEObject, globalParameter, groupObject = self.createHybridABEMultiAuthorityObject(pairingGroup = pairingGroup)
        if creationEpoch is None:
            creationEpoch = nowEpoch
        # Now create the pair of ABE keys for each attribute. Each key set is a dictionary.
        # If no attribute was provided as argument, fetch the attributes from the database.
        if not attributes: # == []
            attributes = locationserviceutility.getAllEntityAttributes(self.entityID, notExpiredBeforeEpoch=nowEpoch,
                                                                       database=database)
            # Check again whether the fetched attributes from the database are empty.
            if not attributes: # == []
                return {}, {}
        # From this point on, we should have something inside attributes.
        (authoritySecretKeys, authorityPublicKeys) = hybridDecentralizedABEObject.authsetup(globalParameter, attributes)

#==============================================================================
#             # 2016.09.14: Let's disable this feature for now. The prorogue, expire functions do not really update the fields within
#             # the dictionaries, therefore the expirationEpoch becomes unmatched with the same field in the database.
#
#             # Put in additional information for future use, such as creation Epoch, expiration, type of pairing curve...
#             # Notice that the current information being added is per "group" of attribute keys, not per single attribute key.
#             # Put additional data (creationEpoch and expirationEpoch) in each attribute key.
#             for authoritySecretKeys_key in authoritySecretKeys:
#                 # Do this if the entry is an inner dictionary.
#                 if isinstance(authoritySecretKeys[authoritySecretKeys_key], dict):
#                     authoritySecretKeys[authoritySecretKeys_key].update({'__creationEpoch__':creationEpoch, '__expirationEpoch__':expirationEpoch})
#
#             for authorityPublicKeys_key in authorityPublicKeys:
#                 # Do this if the entry is an inner dictionary.
#                 if isinstance(authorityPublicKeys[authorityPublicKeys_key], dict):
#                     authorityPublicKeys[authorityPublicKeys_key].update({'__creationEpoch__':creationEpoch, '__expirationEpoch__':expirationEpoch})
#
#==============================================================================
        # Add the pairingCurve type to the whole key set.
        # 2016/08/21 MP: Let's not do this anymore. Allow the keys to be completely empty if no keys were created
        # (for example, for an empty list of attributes). Otherwise, even for empty keys, the elements
        # '__pairingCurve__' and etc. will still be added and will eventually be registered to the database, without any
        # valid keys.
        # Since jsonhelper.py does add the necessary fields for proper deserialization, we do not need the upper level pairing curve fields.
        #authoritySecretKeys.update({'__pairingCurve__':groupObj.param})
        #authorityPublicKeys.update({'__pairingCurve__':groupObj.param})

        # Now save the newly created keys to the database.
        # First convert the ABE keys dictionary to JSON representation for better database manipulation.
        # ABE public keys.
        keyJSON = json.dumps(authorityPublicKeys, cls=jsonhelper.KeyEncoder, pairingCurve=groupObject.param)
        # Save to database.
        if locationserviceutility.registerKeyToDatabase(self.entityID,
                                                        keyJSON, None, constants.ABE_AUTHORITY_PUBLIC_KEY_TYPE,
                                                        "DABE_AW11", creationEpoch = creationEpoch,
                                                        expirationEpoch = expirationEpoch,
                                                        database = database):
            self.log.info("ABE public keys for entity %s created and entered into database %s.", self.entityID, database)
        else:
            self.log.error("Problem registering ABE public keys for entity %s into database %s: valid entry already exists or no key to register!", self.entityID, database)
            #raise SystemExit("Problem registering ABE public keys to database: valid entry already exists or no key to register!")
        # ABE secret keys.
        keyJSON = json.dumps(authoritySecretKeys, cls=jsonhelper.KeyEncoder, pairingCurve=groupObject.param)
        # Save to database.
        if locationserviceutility.registerKeyToDatabase(self.entityID, keyJSON, None, constants.ABE_AUTHORITY_SECRET_KEY_TYPE,
                                   "DABE_AW11", creationEpoch = creationEpoch, expirationEpoch = expirationEpoch,
                                   database = database):
            self.log.info("ABE secret keys for entity %s created and entered into database %s", self.entityID, database)
        else:
            self.log.error("Problem registering ABE secret keys for entity %s into database %s: valid entry already exists or no key to register!", self.entityID, database)
            #raise SystemExit("Problem registering ABE secret keys to database: valid entry already exists or no key to register!")

        return authoritySecretKeys, authorityPublicKeys

    def getABEAuthorityKeys(self, notExpiredBeforeEpoch=None, lastUsedEpoch=None, database=None):
        """
        Return existing and valid ABE authority keys from the database.

        If there are valid, existing keys in the database (i.e., keys from which the expirationEpoch is greater than
        the expirationEpoch as parameter), then return them, both public and secret keys. Otherwise, return empty dict for both.
        Since these public/secret keys exist in pairs, we assume one cannot expire before the other. Obviously, the public
        keys can be recreated given the secret keys, but not the opposite. If the database is in a state wherein only the public
        keys exist, this is an error state. We assume the database also should not contain only the valid secret key, albeit it is
        possible to recreate the public keys from the secret keys. Therefore, it is either both valid and good, or none.

        Parameters
        ----------
        notExpiredBeforeEpoch : epoch
            keys will be retrieved if their expirationEpoch is greater than
            notExpiredBeforeEpoch. If None, time.time() will be utilized.
        lastUsedEpoch : epoch, optional
            the epoch of the recording. Default is None, which will then utilize the current epoch. This is an epoch float.
        database : str
            filename of authority database. If None, utilize the instance default.

        Returns
        -------
        dict, dict
            ABE authority's secret keys, ABE authority's public keys if valid and existent in database.
            Empty dicts for both if no valid, existing key was found.
        """

        # Set database.
        if database is None:
            database = self.database

        nowEpoch = time.time()
        if notExpiredBeforeEpoch is None:
            notExpiredBeforeEpoch = nowEpoch
        if lastUsedEpoch is None:
            lastUsedEpoch = nowEpoch

        # Retrieve ABE secret keys if any (valid ones). Get one merged dictionary of existing keys.
        # locationserviceutility.getEntityKeysOfType returns a list of found keys.
        # locationserviceutility.mergeListOfJsonObjectsIntoOneJson merges a list of dictionaries into one JSON object.
        # In this case, the (possiby) list of dictionaries is the list of ABE keys.
        #abeKeyJSON = locationserviceutility.mergeListOfJsonObjectsIntoOneDictionary.mergeListOfJsonObjectsIntoOneJson(locationserviceutility.getEntityKeysOfType(self.entityID, constants.ABE_AUTHORITY_SECRET_KEY_TYPE, notExpiredBeforeEpoch=notExpiredBeforeEpoch, lastUsedEpoch=lastUsedEpoch, database=database))
        abeSecretKey = locationserviceutility.mergeListOfJsonObjectsIntoOneDictionaryAndDeserialize(locationserviceutility.getEntityKeysOfType(self.entityID, constants.ABE_AUTHORITY_SECRET_KEY_TYPE, notExpiredBeforeEpoch=notExpiredBeforeEpoch, lastUsedEpoch=lastUsedEpoch, database=database))
        #if abeKeyJSON: # Is the JSON object not empty (empty = False)?
        if abeSecretKey: # Is the key dict object not empty (empty = False)?
            # Found. Log.
            self.log.info("ABE secret keys found and retrieved.")
        else:
            # ABE secret keys not found. Log and return immediately with None.
            self.log.info("ABE secret keys not found. Returning immediately with {} for secret/public keys.")
            return {}, {}

        # Retrieve ABE public keys if any (valid ones). Get one dictionary of merged existing keys.
        #abeKeyJSON = locationserviceutility.mergeListOfJsonObjectsIntoOneJson(locationserviceutility.getEntityKeysOfType(self.entityID, constants.ABE_AUTHORITY_PUBLIC_KEY_TYPE, notExpiredBeforeEpoch=notExpiredBeforeEpoch, lastUsedEpoch=lastUsedEpoch, database=database))
        abePublicKey = locationserviceutility.mergeListOfJsonObjectsIntoOneDictionaryAndDeserialize(locationserviceutility.getEntityKeysOfType(self.entityID, constants.ABE_AUTHORITY_PUBLIC_KEY_TYPE, notExpiredBeforeEpoch=notExpiredBeforeEpoch, lastUsedEpoch=lastUsedEpoch, database=database))
        #if abeKeyJSON:
        if abePublicKey:
            # Found. Log and return.
            #abePublicKey = json.loads(abeKeyJSON, cls=jsonhelper.KeyDecoder)
            self.log.info("ABE public keys found and retrieved. Returning both secret and public keys.")
            return abeSecretKey, abePublicKey
        else:
            # ABE public keys not found. Log and return with None for both.
            self.log.info("ABE public keys not found. Returning with {} for secret/public keys.")
            return {}, {}

    def getABEAuthorityPublicKeys(self, notExpiredBeforeEpoch=None, lastUsedEpoch=None, database=None):
        """
        Return existing and valid ABE authority public keys from the database.

        If there are valid, existing public keys in the database (i.e., keys from which the expirationEpoch is greater than
        the expirationEpoch as parameter), then return them. Otherwise, return empty dict.
        Since these public/secret keys exist in pairs, we assume one cannot expire before the other. Obviously, the public
        keys can be recreated given the secret keys, but not the opposite. If the database is in a state wherein only the public
        keys exist, this is an error state. We assume the database also should not contain only the valid secret key, albeit it is
        possible to recreate the public keys from the secret keys. Therefore, it is either both valid and good, or none.

        Parameters
        ----------
        notExpiredBeforeEpoch : epoch
            keys will be retrieved if their expirationEpoch is greater than
            notExpiredBeforeEpoch. If None, time.time() will be utilized.
        lastUsedEpoch : epoch, optional
            the epoch of the recording. Default is None, which will then utilize the current epoch. This is an epoch float.
        database : str
            filename of authority database. If None, utilize the instance default.

        Returns
        -------
        dict
            ABE authority's public keys if valid and existent in database.
            Empty dict if no valid, existing key was found.
        """

        # Set database.
        if database is None:
            database = self.database

        nowEpoch = time.time()
        if notExpiredBeforeEpoch is None:
            notExpiredBeforeEpoch = nowEpoch
        if lastUsedEpoch is None:
            lastUsedEpoch = nowEpoch
        secretKeys, publicKeys = self.getABEAuthorityKeys(notExpiredBeforeEpoch=notExpiredBeforeEpoch, lastUsedEpoch=lastUsedEpoch, database=database)        
        return publicKeys

    def getABEUserKeys(self, userEntityID=None, notExpiredBeforeEpoch=None, lastUsedEpoch=None, database=None):
        """
        Return existing and valid ABE user secret keys from the database.

        If there are valid, existing secret keys in the database (i.e., keys from which the expirationEpoch is greater than
        the expirationEpoch as parameter), then return them. Otherwise, return None.

        Parameters
        ----------
        userEntityID : str
            entityID of the user who owns the secret keys
        notExpiredBeforeEpoch : epoch
            keys will be retrieved if their expirationEpoch is greater than
            notExpiredBeforeEpoch. If None, time.time() will be utilized.
        lastUsedEpoch : epoch, optional
            the epoch of the recording. Default is None, which will then utilize the current epoch. This is an epoch float.
        database : str
            filename of authority database. If None, utilize the instance default.

        Returns
        -------
        dict
            ABE user secret keys if valid and existent in database.
            Empty dict if no valid, existing key was found.
        """
        # TODO: test this function!

        # Set database.
        if database is None:
            database = self.database

        nowEpoch = time.time()
        if notExpiredBeforeEpoch is None:
            notExpiredBeforeEpoch = nowEpoch
        if lastUsedEpoch is None:
            lastUsedEpoch = nowEpoch

        # Retrieve ABE secret keys if any (valid ones). Get one merged dictionary of existing keys.
        # locationserviceutility.getEntityKeysOfType returns a list of found keys.
        # locationserviceutility.mergeListOfJsonObjectsIntoOneJson merges a list of dictionaries into one dictionary.
        # In this case, the (possiby) list of dictionaries is the list of ABE keys.
        #abeKeyJSON = locationserviceutility.mergeListOfJsonObjectsIntoOneJson(locationserviceutility.getEntityKeysOfType(userEntityID, constants.ABE_USER_SECRET_KEY_TYPE, notExpiredBeforeEpoch=notExpiredBeforeEpoch, lastUsedEpoch=lastUsedEpoch, database=database))
        abeSecretKeys = locationserviceutility.mergeListOfJsonObjectsIntoOneDictionaryAndDeserialize(locationserviceutility.getEntityKeysOfType(userEntityID, constants.ABE_USER_SECRET_KEY_TYPE, notExpiredBeforeEpoch=notExpiredBeforeEpoch, lastUsedEpoch=lastUsedEpoch, database=database))
        #if abeKeyJSON: # Is the JSON object not empty (empty = False)?
        if abeSecretKeys: # Is the secret key not empty (empty = False)?
            # Found. Log.
            #abeSecretKeys = json.loads(abeKeyJSON, cls=jsonhelper.KeyDecoder)
            self.log.info("ABE user secret keys found and retrieved.")
            return abeSecretKeys
        else:
            # ABE secret keys not found. Log and return immediately with None.
            self.log.info("ABE user secret keys not found. Returning immediately with {} for secret keys.")
            return {}



    def getOrCreateABEAuthorityKeys(self, attributes=[], pairingGroup=constants.DEFAULT_PAIRING_GROUP,
                                    notExpiredBeforeEpoch=None, creationEpoch=None,
                                    expirationEpoch=None, database=None):
        """
        Returns existing, valid ABE authority keys from the database, or create new ones of no valid ones were
        found.

        Note: valid keys are considered those which expirationEpoch is greater than time.time().

        This function will first call getABEAuthorityKeys function to verify whether valid, existing keys could
        be retrieved from the database. Return those keys if found, otherwise call the function createABEAuthorityKeys()
        to create and register new set of secret/public keys.

        This way, this function will always return a set of secret/public ABE keys for the authority, whether those
        keys are existing valid keys, or newly created ones.

        Parameters
        ----------
        attributes : list of str, optional, default empty list
            list of string attributes to which create keys.
        pairingGroup : str, optional
            PairingGroup name with which ABE keys are to be created. Default is constants.DEFAULT_PAIRING_GROUP.
        notExpiredBeforeEpoch : epoch, optional
            keys will be retrieved if their expirationEpoch is greater than
            notExpiredBeforeEpoch. If None, time.time() will be utilized. Typically, this parameter should be left blank,
            such that None and then time.time() is utilized. Using something other than time.time() without
            full understanding of the consequences might yield undesired results, such as attempting to create
            keys when valid keys already exist. In this case, an exception will be produced by the function
            that creates new keys.
        creationEpoch : epoch, optional
            epoch when the key was registered to the database. Will default to time.time() if not specified.
        expirationEpoch : epoch, optional
            epoch of the expiration date of this key.
        database : str, optional
            filename of database. If None, default instance database will be utilized.

        Returns
        -------
        dict, dict
            Secret ABE keys for the authority.
            Public ABE keys for the authority.
            (Existing ones, or newly created ones. There should not be the case wherein empty dicts are returned.)

        Notes
        -----
        2016.10.25: In the current implementation, expirationEpoch cannot be NULL in the database. Not passing its value
        as argument for this function will result in sqlite3 exception.
        """

        # Secret, public.
        nowEpoch = time.time()
        # Set database.
        if database is None:
            database = self.database
        if creationEpoch is None:
            creationEpoch = nowEpoch
        if notExpiredBeforeEpoch is None:
            notExpiredBeforeEpoch = nowEpoch
        # Attempt to get existing, valid ABE authority keys from the database.
        secretABEkeys, publicABEkeys = self.getABEAuthorityKeys(notExpiredBeforeEpoch = notExpiredBeforeEpoch, database = database)
        # If empty dict is obtained, then create new keys. Otherwise, return with the obtained keys from teh database.
        if secretABEkeys:
            return secretABEkeys, publicABEkeys # If one is None, the other one is always None also.
        # Else, create and return new keys.
        else:
            return self.createABEAuthorityKeys(attributes=attributes, pairingGroup = pairingGroup,
                                               expirationEpoch = expirationEpoch, database = database)

    def expireABEAuthorityKeys(self, notExpiredBeforeEpoch=None, lastUsedEpoch=None, database=None):
        """
        Expires existing ABE authority's public and secret keys.

        The function will search for secret and public ABE keys which expirationEpoch is greater than
        notExpiredBeforeEpoch. If found, the function will update that field (expirationEpoch) with the value of
        notExpiredBeforeEpoch, and also update lastUsedEpoch field with the parameter value or time.time() if not
        specified.

        Therefore, the function will not extend expiration epoch of keys, but only update expirationEpoch to
        lower values than current ones.

        Parameters
        ----------
        notExpiredBeforeEpoch : epoch, optional
            keys will be retrieved if their expirationEpoch is greater than
            notExpiredBeforeEpoch. If None, time.time() will be utilized.
        lastUsedEpoch : epoch, optional
            the epoch of the recording. Default is None, which will then utilize the current epoch. This is an epoch float.
        database : str, optional
            filename of authority database. If None, utilize the instance default.

        Returns
        -------
        int
            Number of rows updated.
        """

        nowEpoch = time.time()
        # Set database.
        if database is None:
            database = self.database

        if notExpiredBeforeEpoch is None:
            notExpiredBeforeEpoch = nowEpoch

        if lastUsedEpoch is None:
            lastUsedEpoch = nowEpoch

        # Use the utility function.
        totalExpired = locationserviceutility.expireKeysOfType(self.entityID, [constants.ABE_AUTHORITY_PUBLIC_KEY_TYPE, constants.ABE_AUTHORITY_SECRET_KEY_TYPE],
                                                               notExpiredBeforeEpoch=notExpiredBeforeEpoch, lastUsedEpoch=lastUsedEpoch, database=database)
        self.log.info("Number of ABE authority keys expired: %s", totalExpired)
        return totalExpired


    def prorogueABEAuthorityKeys(self, newExpirationEpoch=None, lastUsedEpoch=None, database=None):
        """
        Extend or postpone expirationEpoch of existing keys, if their expirationEpoch is greater than time.time() (i.e., the
        keys are still valid). We will not postpone expiration of already expired keys, lest creating "zombies".


        Should we only allow prorogation, or actually updating the expirationEpoch to a lower value than
        the original?

        Parameters
        ----------
        newExpirationEpoch : epoch
            new expiration epoch for valid keys.
        lastUsedEpoch : epoch
            the epoch of the updating. If None, use time.time().
        database : str
            filename of authority database. If None, utilize the instance default.

        Returns
        -------
        int
            Number of key tuples with expirationEpoch postponed.
        """

        nowEpoch = time.time()
        # Set database.
        if database is None:
            database = self.database

        # Return immediately in the case below. There has to be a newExpirationEpoch.
        if newExpirationEpoch is None:
            return 0

        if lastUsedEpoch is None:
            lastUsedEpoch = nowEpoch

        # To prorogue, set expirationEpoch to newExpirationEpoch if newExpirationEpoch > expirationEpoch AND
        # expirationEpoch > time.time() (i.e., key is still valid, not expired).
        # Use utility function.
        totalProrogued = locationserviceutility.prorogueKeysOfType(self.entityID, [constants.ABE_AUTHORITY_PUBLIC_KEY_TYPE, constants.ABE_AUTHORITY_SECRET_KEY_TYPE],
                                                                   newExpirationEpoch=newExpirationEpoch, lastUsedEpoch=lastUsedEpoch, database=database)
        self.log.info("Number of ABE authority keys prorogued: %s", totalProrogued)
        return totalProrogued


    def expireABEUserAttributeKeys(self, userEntityID, attributes=[], notExpiredBeforeEpoch=None, lastUsedEpoch=None, database=None):
        """
        Expires existing ABE user's secret keys.

        The function will search for secret ABE keys which expirationEpoch is greater than
        notExpiredBeforeEpoch. If found, the function will update that field (expirationEpoch) with the value of
        notExpiredBeforeEpoch, and also update lastUsedEpoch field with the parameter value or time.time() if not
        specified.

        Therefore, the function will not extend expiration epoch of keys, but only update expirationEpoch to
        lower values than current ones.

        Parameters
        ----------
        userEntityID : str
            entityID of the user owner of the ABE private keys
        attributes : list of str, optional
            list of attributes from which keys will be expired. If empty, all ABE user keys will be expired.
        notExpiredBeforeEpoch : epoch, optional
            keys will be retrieved if their expirationEpoch is greater than
            notExpiredBeforeEpoch. If None, time.time() will be utilized.
        lastUsedEpoch : epoch, optional
            the epoch of the recording. Default is None, which will then utilize the current epoch. This is an epoch float.
        database : str, optional
            filename of authority database. If None, utilize the instance default.

        Returns
        -------
        int
            Number of rows updated (expired).
        """

        nowEpoch = time.time()
        # Set database.
        if database is None:
            database = self.database

        if notExpiredBeforeEpoch is None:
            notExpiredBeforeEpoch = nowEpoch

        if lastUsedEpoch is None:
            lastUsedEpoch = nowEpoch

        # Fetch all existing ABE user keys. They will come as sqlite3.Row objects.
        existingKeysRows = locationserviceutility.getEntityKeysOfTypeWholeTuple(userEntityID, constants.ABE_USER_SECRET_KEY_TYPE, notExpiredBeforeEpoch=notExpiredBeforeEpoch, lastUsedEpoch=lastUsedEpoch, database=database)
        # Get the list of attributes issued by this authority to this userEntityID. Use the same notExpiredBeforeEpoch.
        registeredUserAttributes = locationserviceutility.getAllAttributesIntersectionTwoEntities(self.entityID, userEntityID, notExpiredBeforeEpoch=notExpiredBeforeEpoch, database=self.database)

        if attributes: # if attributes is not empty
            # Filter from the attributes in the argument, any that is not registered to the user and issued by this authority.
            # Ensure the letter case is the same.
            attributes = list(set(map(str.lower, attributes)) & set(map(str.lower, registeredUserAttributes)))
        else:
            # attributes is empty. Let it be the whole set of attributes registered to the user by the authority.
            attributes = registeredUserAttributes

        # For each returned row, deserialize the key, check whether the attribute is in the argument, and if it is, expire it.
        # Only consider attributes that are owned by this authority. Disregard any other (should the Location Service have
        # the power to expire any attribute key?).
        # Expire the key (setting expirationEpoch to notExpiredBefore) and set lastUsedEpoch to the value in the argument
        # (even though the lastUsedEpoch was already updated by the function getEntityKeysOfTypeWholeTuple, but we do not
        # assume this function should always do it).
        rowPrimaryKeysToExpireList = []
        con = sqlite3.connect(database)
        for row in existingKeysRows:
            deserializedKey = json.loads(row['key'], jsonhelper.KeyDecoder)
            # If the attribute was issued by this authority, go ahead and expire it; otherwise, disregard it.
            # Use sets. If set(deserialized.keys()) is a subset of set(attributes), then ok to expire it.
            # This means all the attributes in this key were issued by the authority. Note that this scheme accepts
            # more than one attribute per key, even though other functions ensure (or expect) there is only one attribute
            # per key.
            # Ref.: http://stackoverflow.com/questions/6159313/can-python-test-the-membership-of-multiple-values-in-a-list
            # This piece of code (2 lines) is the security component that disallows an authority (or any entity) from
            # expiring keys of another entity, if those keys happen to exist in the same database and with access.
            # In effect, a user database will have secret keys issued by many authorities, whereas an authority database
            # will typically only have secret keys issued by itself.
            # In comparison, the reason why some user cannot log in to a system utilizing any password is because the
            # system will run some if statement and deny access.
            if set(map(str.lower, deserializedKey.keys())) <= set(map(str.lower, attributes)):
                # Add the row to the list to process later.
                rowPrimaryKeysToExpireList.append(row['primaryKey'])
        # Now process the list of rows to update in a single SQL statement.
        placeHolders = locationserviceutility._constructPlaceHolder(rowPrimaryKeysToExpireList)
        query = "update entityKey set expirationEpoch=?, lastUsedEpoch=? where primaryKey in %s" % placeHolders
        with con:
            con.execute(query, [notExpiredBeforeEpoch, lastUsedEpoch] + rowPrimaryKeysToExpireList)
            # Sanity check.
            if con.total_changes != len(rowPrimaryKeysToExpireList):
                self.log.error("Sanity check failed. Expired number of rows different from expected.")
                raise SystemExit("Sanity check failed. Expired number of rows different from expected.")
        self.log.info("Number of ABE user %s keys expired: %s", userEntityID, con.total_changes)
        return con.total_changes


    def prorogueABEUserAttributeKeys(self, userEntityID, attributes=[], newExpirationEpoch=None, lastUsedEpoch=None, database=None):
        """
        Extend or postpone expirationEpoch of existing ABE user keys, if their expirationEpoch is greater than time.time() (i.e., the
        keys are still valid). We will not postpone expiration of already expired keys, lest creating "zombies".

        To prorogue, set expirationEpoch to newExpirationEpoch if newExpirationEpoch > expirationEpoch AND
        expirationEpoch > time.time() (i.e., key is still valid, not expired).

        Parameters
        ----------
        userEntityID : str
            entityID of the user owner of the ABE private keys
        attributes : list of str, optional
            list of attributes from which keys will be expired. If empty, all ABE user keys (of this authority) will be prorogued.
        newExpirationEpoch : epoch, optional
            new expiration epoch for valid keys. If None, use time.time().
        lastUsedEpoch : epoch, optional
            the epoch of the recording. Default is None, which will then utilize the current epoch. This is an epoch float.
        database : str, optional
            filename of authority database. If None, utilize the instance default.

        Returns
        -------
        int
            Number of rows updated (prorogued).
        """

        nowEpoch = time.time()
        # Set database.
        if database is None:
            database = self.database

        # Return immediately in the case below. There has to be a newExpirationEpoch.
        if newExpirationEpoch is None:
            return 0

        if lastUsedEpoch is None:
            lastUsedEpoch = nowEpoch

        # Fetch all existing and valid ABE user keys. They will come as sqlite3.Row objects.
        existingKeysRows = locationserviceutility.getEntityKeysOfTypeWholeTuple(userEntityID, constants.ABE_USER_SECRET_KEY_TYPE, notExpiredBeforeEpoch=nowEpoch, lastUsedEpoch=lastUsedEpoch, database=database)
        # Get the list of attributes issued by this authority to this userEntityID.
        registeredUserAttributes = locationserviceutility.getAllAttributesIntersectionTwoEntities(self.entityID, userEntityID, notExpiredBeforeEpoch=nowEpoch, database=self.database)

        if attributes: # if attributes is not empty
            # Filter from the attributes in the argument, any that is not registered to the user and issued by this authority.
            # Ensure the letter case is the same.
            attributes = list(set(map(str.lower, attributes)) & set(map(str.lower, registeredUserAttributes)))
        else:
            # attributes is empty. Let it be the whole set of attributes registered to the user by the authority.
            attributes = registeredUserAttributes

        # For each returned row, deserialize the key, check whether the attribute is in the argument, and if it is, prorogue it.
        # Only consider attributes that are owned by this authority. Disregard any other (should the Location Service have
        # the power to expire any attribute key?).
        # Prorogue the key (setting expirationEpoch to newExpirationEpoch) and set lastUsedEpoch to the value in the argument
        # (even though the lastUsedEpoch was already updated by the function getEntityKeysOfTypeWholeTuple, but we do not
        # assume this function should always do it).
        rowPrimaryKeysToProrogueList = []
        con = sqlite3.connect(database)
        for row in existingKeysRows:
            deserializedKey = json.loads(row['key'], jsonhelper.KeyDecoder)
            # If the attribute was issued by this authority, go ahead and prorogue it; otherwise, disregard it.
            # Use sets. If set(deserialized.keys()) is a subset of set(attributes), then ok to expire it.
            # This means all the attributes in this key were issued by the authority. Note that this scheme accepts
            # more than one attribute per key, even though other functions ensure (or expect) there is only one attribute
            # per key.
            # Ref.: http://stackoverflow.com/questions/6159313/can-python-test-the-membership-of-multiple-values-in-a-list
            # This piece of code (2 lines) is the security component that disallows an authority (or any entity) from
            # proroguing keys of another entity, if those keys happen to exist in the same database and with access.
            # In effect, a user database will have secret keys issued by many authorities, whereas an authority database
            # will typically only have secret keys issued by itself.
            # In comparison, the reason why some user cannot log in to a system utilizing any password is because the
            # system will run some if statement and deny access.
            # The test: row['expirationEpoch'] < newExpirationEpoch
            # => Only prorogue keys for which expirationEpoch occurs before newExpirationEpoch (otherwise we are not proroguing it, but abbreviating the key).
            # As a matter of fact, we do not have a function to abbreviate a key's expiration. In this case, we should simply expire it and reissue?
            if set(map(str.lower, deserializedKey.keys())) <= set(map(str.lower, attributes)) and row['expirationEpoch'] < newExpirationEpoch:
                # Add the row to the list to process later.
                rowPrimaryKeysToProrogueList.append(row['primaryKey'])
        # Now process the list of rows to update in a single SQL statement.
        placeHolders = locationserviceutility._constructPlaceHolder(rowPrimaryKeysToProrogueList)
        # Only prorogue keys for which expirationEpoch occurs before newExpirationEpoch (otherwise we are not proroguing it, but abbreviating the key).
        # As a matter of fact, we do not have a function to abbreviate a key's expiration. In this case, we should simply expire it and reissue?
        query = "update entityKey set expirationEpoch=?, lastUsedEpoch=? where primaryKey in %s" % placeHolders
        with con:
            con.execute(query, [newExpirationEpoch, lastUsedEpoch] + rowPrimaryKeysToProrogueList)
            # Sanity check.
            if con.total_changes != len(rowPrimaryKeysToProrogueList):
                self.log.error("Sanity check failed. Prorogued number of rows (%s) different from expected (%s).", con.total_changes, len(rowPrimaryKeysToProrogueList))
                raise SystemExit("Sanity check failed. Prorogued number of rows different from expected.")
        self.log.info("Number of ABE user %s keys prorogued: %s", userEntityID, con.total_changes)
        return con.total_changes


    def createABEUserKeys(self, userEntityID=None, attributes=[], pairingGroup=constants.DEFAULT_PAIRING_GROUP, creationEpoch=None, expirationEpoch=None, database=None):
        """
        Through this function, the authority can create secret ABE keys for a user based on that user's assigned attributes.

        Upon calling the function to generate the ABE secret keys for a user, the return is a dictionary of keys, one
        key per attribute of the user. This function can call the creation of all keys at once, but will register them
        to the database one attribute-key at a time.

        If the attributes are specified as arguments, then only these attributes will be utilized to generate the keys. If none are
        specified (i.e., the default empty list is used), then the attributes belonging to the user will be retrieved from
        the database. However, from this list of attributes, only those that has the authority as "owner" can be utilized for
        the generation (otherwise the ABE module will throw an exception).

        Parameters
        ----------
        userEntityID : str, (not really optional)
            entityID of the user who will receive the ABE user keys
        attributes : list of str, optional
            list of attributes, for which the keys will be generated. If list is empty (default), then attributes will be fetched from the database
        pairingGroup : str, optional
            PairingGroup name with which ABE keys are to be created. Default is constants.DEFAULT_PAIRING_GROUP.
        creationEpoch : epoch, optional
            epoch when the key was registered to the database. Will default to time.time() if not specified.
        expirationEpoch : epoch, optional
            epoch of the expiration date of this key.
        database : str, optional
            filename of database. If None, default instance database will be utilized.

        Returns
        -------
        dict, list of str
            dictionary containing the ABE secret keys for the user, one per attribute.
            list of serialized (JSON) keys, as str, wherein each element is the JSON serialized ABE secret key. The
            two structures return the same keys (one is a full dict with all keys, the other is a list of individual,
            serialized keys).

        Notes
        -----
        The two structures return the same keys (one is a full dict with all keys, the other is a list of individual,
        serialized keys).
        If there are no attributes either as argument or in the database, the return will be an empty dict.
        If there are existing, valid keys for all attributes in the database, the return will be an empty dict.
        2016.10.25: In the current implementation, expirationEpoch cannot be NULL in the database. Not passing its value
        as argument for this function will result in sqlite3 exception.

        """

        nowEpoch = time.time()
        # Set database.
        if database is None:
            database = self.database

        # We now retrieve valid, existing ABE user keys from the database. If an attribute in the attribute argument list
        # matches one of those valid keys, then a new key will not be generated for that attribute (it will be skipped).
        # Note that a user can only have one ABE secret key per attribute, since attributes are globally unique.
        # An authority can only generate user keys for attributes for which they have ABE authority secret keys.
        # An authority can attempt to "hijack" an attribute that was not assigned to that authority and generate
        # ABE authority secret keys for it, and hence ABE user keys for that attribute.
        # However, ciphertexts generated with the "genuine" authority keys for that attribute cannot be decrypted
        # with the "hijacked" keys.
        # The way the D-ABE cryptosystem works, the decryption and user key generation functions will fail if the proper
        # authority keys were not utilized to encrypt the text and generate the user keys.
        # Obviously, ciphertexts created by the "hijacking" authority with the "hijacked" attribute keys can be decrypted
        # by users possessing keys issued by the "hijacking" authority. But then there will be a conflict between the
        # genuine authority and the "hijacking" one, and the cryptosystem will reveal that.

        # Note: valid keys are considered those which expirationEpoch is greater than time.time().
        existingKeys = self.getABEUserKeys(userEntityID=userEntityID, notExpiredBeforeEpoch=nowEpoch, database=database)
        if creationEpoch is None:
            creationEpoch = nowEpoch
        # Now just generate user keys (into a dictionary) for all attributes. We will decide the ones to use later.
        # But first, decide whether to use the attributes passed as arguments, if any, or to fetch them from the database.
        # If no attribute was provided as argument, fetch the attributes from the database (attributes belonging to the user
        # and the authority at the same time).
        if not attributes: # == []
            attributes = locationserviceutility.getAllAttributesIntersectionTwoEntities(userEntityID, self.entityID,
                                                                                        notExpiredBeforeEpoch=nowEpoch,
                                                                                        database=database)
            # Check again whether the fetched attributes from the database are empty. If there are no attributes, we cannot proceed.
            if not attributes: # == []
                return {}, []
        # From this point on, we should have something inside attributes. Now use Charm Crypto to create the user keys.
        # From attributes, filter out those that have existing, valid keys. For those, we will not create new keys.
        # Note that, here, attributes as keys in the database are always in uppercase (since dabe_aw11 will convert all
        # string attributes to uppercase), but that is not necessarily true in this system's database. As such,
        # direct operations with sets will not work if equal attributes do not have the same case. Therefore, we must
        # normalize the case here before doing any set operation.
        # Let's use the solution at http://stackoverflow.com/questions/1479979/case-insensitive-comparison-of-sets-in-python
        attributes = set(map(str.lower, attributes)) - set(map(str.lower, existingKeys))
        # attributes is now a set, not a list. Should not make a difference. attributes now only contains attributes that have no valid keys
        # in the database.
        # Upon calling _generateAbeUserKeys, abeUserKeys will have a dict with the ABE secret keys. gid is filtered out.
        abeUserKeys, hybridAbeMaObject, globalParameter, groupObject  = self._generateAbeUserKeys(userEntityID, attributes, pairingGroup=pairingGroup)

        # Now save the newly created keys to the database.
        # Use a loop to iterate through the dict such that each key/attribute is registered to the database separately.
        serializedAbeUserKeysList = []
        for key, value in abeUserKeys.items():
            # First convert the ABE keys dictionary to JSON representation for better database manipulation.
            individualKeyJson = json.dumps({key:value}, cls=jsonhelper.KeyEncoder, pairingCurve=groupObject.param)
            # Save to database.
            if locationserviceutility.registerKeyToDatabase(userEntityID,
                                                            individualKeyJson, None, constants.ABE_USER_SECRET_KEY_TYPE,
                                                            "DABE_AW11", creationEpoch = creationEpoch,
                                                            expirationEpoch = expirationEpoch,
                                                            database = database):
                self.log.info("ABE user secret key for entity %s created and entered into database %s.", userEntityID, database)
                # Add the individual serialized attribute key to the list of serialized keys to be returned.
                serializedAbeUserKeysList.append(individualKeyJson)
            else:
                self.log.error("Problem registering ABE user secret key for entity %s, attribute %s, into database %s: valid entry already exists or no key to register!", userEntityID, key, database)
                # Remove the problematic key from the list of generated keys to be returned. There shouldn't be any problems
                # with registering keys, actually, as the attributes were filtered for existing keys. If there is a problem,
                # then perhaps the whole process should be halted here with an exception...
                abeUserKeys.pop(key)
                #raise SystemExit("Problem registering ABE user secret key for entity into database: valid entry already exists or no key to register!)

        return abeUserKeys, serializedAbeUserKeysList


    def _generateAbeUserKeys(self, userEntityID, attributes, pairingGroup=constants.DEFAULT_PAIRING_GROUP):
        """
        This function simplifies the use of dabenc_adapt_hybrid keygen function. In particular, it will enable the generation
        of keys for a list of attributes, instead of only one attribute.

        The function will also generate its own HybridABEncMA (dabenc_adapt_hybrid.py) object as appropriate and return the
        object, the globalParameter, and the PairingGroup object, which the user can make use of for other purposes, such
        as passing PairingGroup PairingCurve as argument to JSON helper.

        Parameters
        ----------
        userEntityID : str
            entityID of the ABE user for whom keys will be generated
        attributes : list of str
            list of attributes for ABE user key generation.

        Returns
        -------
        dict, object, object, object
            dictionary of ABE user secret keys, one per attribute,
            HybridABEncMA object,
            globalParameter (from HybridABEncMA.setup method) object,
            PairingGroup object
        """
        hybridDecentralizedABEObject, globalParameter, groupObject = self.createHybridABEMultiAuthorityObject(pairingGroup = pairingGroup)
        # The keygen method takes one attribute at a time as str, and updates the user key dictionary. We build a loop here.
        abeUserKeys = {} # Begin with an empty dictionary.
        for attribute in attributes:
            hybridDecentralizedABEObject.keygen(globalParameter, self.abeSecretKeys, attribute, userEntityID, abeUserKeys)
        # Done. Remove the "gid" key:value from the dictionary, inserted there by Charm Crypto and not needed here.
        # Avoid KeyError exception by adding a '' within the pop.
        abeUserKeys.pop(constants.CHARM_CRYPTO_DECENTRALIZED_ABE_GID_KEY, '')
        return abeUserKeys, hybridDecentralizedABEObject, globalParameter, groupObject


    def expireABEAuthorityKeysDeprecated(self, notExpiredBeforeEpoch=None, lastUsedEpoch=None, database=None):
        """
        Expires existing ABE authority's public and secret keys.

        The function will search for secret and public ABE keys which expirationEpoch is greater than
        notExpiredBeforeEpoch. If found, the function will update that field (expirationEpoch) with the value of
        notExpiredBeforeEpoch, and also update lastUsedEpoch field with the parameter value or time.time() if not
        specified.

        Therefore, the function will not extend expiration epoch of keys, but only update expirationEpoch to
        lower values than current ones.

        notExpiredBeforeEpoch: keys will be retrieved if their expirationEpoch is greater than
            notExpiredBeforeEpoch. If None, time.time() will be utilized.
        lastUsedEpoch: the epoch of the recording. Default is None, which will then utilize the current epoch. This is an epoch float.
        database: filename of authority database. If None, utilize the instance default.

        Return:
        Number of rows updated.

        .. warning:: This function is deprecated. Do not use.
        """

        nowEpoch = time.time()
        # Set database.
        if database is None:
            database = self.database

        if notExpiredBeforeEpoch is None:
            notExpiredBeforeEpoch = nowEpoch

        if lastUsedEpoch is None:
            lastUsedEpoch = nowEpoch

        con = sqlite3.connect(database)
        # To expire, set expirationEpoch to notExpiredBeforeEpoch (typically time.time()).
        with con:
            con.execute("""update entityKey """
                        """set expirationEpoch=?, lastUsedEpoch=? """
                        """where entityFk=(select primaryKey from entity where entityID=?) and """
                        """keyTypeFk in (select primaryKey from keyType where keyType=? or keyType=?) and """
                        """expirationEpoch > ?""",
                        (notExpiredBeforeEpoch, lastUsedEpoch, self.entityID, constants.ABE_AUTHORITY_SECRET_KEY_TYPE,
                         constants.ABE_AUTHORITY_PUBLIC_KEY_TYPE, notExpiredBeforeEpoch))

        self.log.info("Number of ABE keys expired: %s", con.total_changes)
        return con.total_changes


    def prorogueABEAuthorityKeysDeprecated(self, newExpirationEpoch=None, lastUsedEpoch=None, database=None):
        """
        Extend or postpone expirationEpoch of existing keys, if their expirationEpoch is greater than time.time() (i.e., the
        keys are still valid). We will not postpone expiration of already expired keys, lest creating "zombies".


        Should we only allow prorogation, or actually updating the expirationEpoch to a lower value than
        the original?

        newExpirationEpoch: new expiration epoch for valid keys.
        lastUsedEpoch: the epoch of the updating. If None, use time.time().
        database: filename of authority database. If None, utilize the instance default.

        Return:
        Number of key tuples with expirationEpoch postponed.

        .. warning:: This function is deprecated. Do not use.
        """

        nowEpoch = time.time()
        # Set database.
        if database is None:
            database = self.database

        # Return immediately in the case below. There has to be a newExpirationEpoch.
        if newExpirationEpoch is None:
            return 0

        if lastUsedEpoch is None:
            lastUsedEpoch = nowEpoch

        con = sqlite3.connect(database)
        # To prorogue, set expirationEpoch to newExpirationEpoch if newExpirationEpoch > expirationEpoch AND
        # expirationEpoch > time.time() (i.e., key is still valid, not expired).
        with con:
            con.execute("""update entityKey """
                        """set expirationEpoch=?, lastUsedEpoch=? """
                        """where entityFk=(select primaryKey from entity where entityID=?) and """
                        """keyTypeFk in (select primaryKey from keyType where keyType=? or keyType=?) and """
                        """expirationEpoch > ? and expirationEpoch < ?""",
                        (newExpirationEpoch, lastUsedEpoch, self.entityID, constants.ABE_AUTHORITY_SECRET_KEY_TYPE,
                         constants.ABE_AUTHORITY_PUBLIC_KEY_TYPE, nowEpoch, newExpirationEpoch))

        self.log.info("Number of ABE keys prorogued: %s", con.total_changes)
        return con.total_changes

    def getABEAuthorityKeysDeprecated(self, notExpiredBeforeEpoch=None, database=None):
        """
        Return existing and valid ABE authority keys from the database.

        If there are valid, existing keys in the database (i.e., keys from which the expirationEpoch is greater than
        the expirationEpoch as parameter), then return them, both public and secret keys. Otherwise, return None for both.
        Since these public/secret keys exist in pairs, we assume one cannot expire before the other. Obviously, the public
        keys can be recreated given the secret keys, but not the opposite. If the database is in a state wherein only the public
        keys exist, this is an error state. We assume the database also should not contain only the valid secret key, albeit it is
        possible to recreate the public keys from the secret keys. Therefore, it is either both valid and good, or none.

        notExpiredBeforeEpoch: keys will be retrieved if their expirationEpoch is greater than
            notExpiredBeforeEpoch. If None, time.time() will be utilized.
        database: filename of authority database. If None, utilize the instance default.

        Return:
        ABE authority's secret keys, ABE authority's public keys if valid and existent in database.
        None for both if no valid, existing key was found.

        .. warning:: This function is deprecated. Do not use.
        """

        # Set database.
        if database is None:
            database = self.database

        if notExpiredBeforeEpoch is None:
            notExpiredBeforeEpoch = time.time()

        con = sqlite3.connect(database)
        with con:
            # Retrieve ABE secret keys if any (valid ones).
            abeKeyJSON = con.execute("""select key from entityKey where """
                                 """entityFk=(select primaryKey from entity where entityID=?) and """
                                 """keyTypeFk in (select primaryKey from keyType where keyType=?) and """
                                 """expirationEpoch > ?""",
                                 (self.entityID, constants.ABE_AUTHORITY_SECRET_KEY_TYPE, notExpiredBeforeEpoch)).fetchone() # The expirationEpoch > time.time() here will fetch non-expired entries.
        if abeKeyJSON:
            # Found. Convert from JSON into dictionary.
            abeSecretKey = json.loads(abeKeyJSON[0], cls=jsonhelper.KeyDecoder)
            self.log.info("ABE secret keys found and retrieved.")
        else:
            # ABE secret keys not found. Log and return immediately with None.
            self.log.info("ABE secret keys not found. Returning immediately with None for secret/public keys.")
            return None, None

        with con:
            # Retrieve ABE public keys if any (valid ones).
            abeKeyJSON = con.execute("""select key from entityKey where """
                                 """entityFk=(select primaryKey from entity where entityID=?) and """
                                 """keyTypeFk in (select primaryKey from keyType where keyType=?) and """
                                 """expirationEpoch > ?""",
                                 (self.entityID, constants.ABE_AUTHORITY_PUBLIC_KEY_TYPE, notExpiredBeforeEpoch)).fetchone() # The expirationEpoch > time.time() here will fetch non-expired entries.
        if abeKeyJSON:
            # Found. Convert from JSON into dictionary.
            abePublicKey = json.loads(abeKeyJSON[0], cls=jsonhelper.KeyDecoder)
            self.log.info("ABE public keys found and retrieved. Returning both secret and public keys.")
            return abeSecretKey, abePublicKey
        else:
            # ABE public keys not found. Log and return with None for both.
            self.log.info("ABE public keys not found. Returning with None for secret/public keys.")
            return None, None

			