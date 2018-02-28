# -*- coding: utf-8 -*-
"""
Created on Tue Apr  5 18:00:43 2016

@author: locksmith
"""

import logging
import time
import sqlite3
from charm.schemes.abenc.dabe_aw11 import Dabe
from charm.adapters.dabenc_adapt_hybrid import HybridABEncMA
import constants
import json
import jsonhelper
import Crypto.Random
import Crypto.Random.random
import base64
import onetimepass
import ast
from charm.toolbox.pairinggroup import PairingGroup
from charm.core.math.pairing import hashPair # SHA256 in Charm Crypto v0.50
import Crypto.Hash.SHA256
import Crypto.Hash.HMAC
import math
import struct
import Crypto.Random
import charm.toolbox.symcrypto

# Configure logger and other file-scope variables.
# Set filename and logging level for log messages, and output formats.
FORMAT = "%(asctime)s;%(levelname)s;%(message)s"
DATEFORMAT = '%Y-%m-%d %H:%M:%S'
formatter = logging.Formatter(fmt=FORMAT, datefmt=DATEFORMAT)
log = logging.getLogger(__name__)
handler = logging.FileHandler(__name__+'.log')
log.setLevel(logging.DEBUG)
handler.setFormatter(formatter)
log.addHandler(handler)

debug = False # If True, print debugging messages.

def registerKeyToDatabase(entityID, key, salt, keyType, algorithm,
                          creationEpoch=None, expirationEpoch=None, lastUsedEpoch=None, database=None):
    """
    Registers a password hash or secret key for a specific `entityID` to the specified database, including the given salt used to compute the hash if any,
    the algorithm utilized to compute the key if any, and the time of utilization. If there is an entry with the same `entityID`, `key`, `salt`, `algorithm`, `keyType`,
    and still valid (i.e., `expirationEpoch` greater than time.time()), the function returns **False**, otherwise returns **True**.

    Parameters
    -----------
    entityID : str
        ID of the entity who owns the hash as string.
    key : byte str
        key to record to the database, as byte string.
    salt : byte str
        salt utilized to compute the password as byte string.
    keyType : str
        the type string of key recorded here; the function will query the appropriate foreign key. Types are defined within the database.
    algorithm : str
        algorithm that computed the key, as string (e.g., 'PBKDF2-HMAC-SHA256').
    creationEpoch : epoch, optional
        epoch when the key was registered to the database.
    expirationEpoch : epoch, optional
        epoch of the expiration date of this key.
    lastUsedEpoch : epoch, optional
        the epoch of the recording. Default is None, which will then utilize the current epoch. This is an epoch float.
    database : str
        filename of database. If `None`, an exception will be raised.

    Returns
    -------
    bool
        **True** if the registration was successful; **False** if a similar record (but for the `lastTimeUsed`) was found.

    Notes
    -----
    Perhaps the function should update the `lastTimeUsed` if a similar record is found?
    """

    nowEpoch = time.time()
    # Check whether database was passed as argument.
    if database is None:
        # Exit immediately after logging error.
        log.error("Database filename is None. It must not be undefined.")
        raise SystemExit("Database filename is None. It must not be undefined.")

    # If the key is empty (string '{}'), we cannot proceed. It so happens that SQLite will store the string '{}'.
    # Cannot do this here! The key can be any byte string, therefore could be any "empty" representation... best to
    # test this in the calling function.
    #if key == '{}':
    #    return False

    # Fetch the keyType primary key.
    keyTypeFk = getKeyTypePk(keyType, database=database)
    # Verify whether same entry already exists in database.
    con = sqlite3.connect(database)
    with con:
        # If the key is expired, we can insert the same one with new expiration date. Why not just update the expiration date? I do not know.
        # Note that we use "is" instead of = here for the comparisons. We find that "= NULL" does not work (and throws no exception), which
        # causes bad behavior when, for example, the salt parameter is None. The select will fail to retrieve rows when
        # salt is NULL and salt parameter is None, because the test Null = Null is not true in SQLITE!
        # However, "is" always work as a substitute for =.
        result = con.execute("""select * from entityKey where """
                             """entityFk=(select primaryKey from entity where entityID=?) and """
                             """key is ? and salt is ? and keyTypeFk is ? and algorithm is ? and """
                             """expirationEpoch > ?""",
                             (entityID, key, salt, keyTypeFk, algorithm, nowEpoch)).fetchall() # The expirationEpoch > time.time() here will fetch non-expired entries.
        # If something was found, then record already exists and it is still valid (expirationEpoch <= time.time()) for the key and salt. Return False.
        if result:
            log.warning("There is an equal, valid key record in the database %s. Nothing was done.", database)
            return False

        # Record does not exist. Insert.
        # Define creationEpoch and lastUsedEpoch to current time if values were not passed as arguments.
        if creationEpoch is None:
            creationEpoch = nowEpoch
        if lastUsedEpoch is None:
            lastUsedEpoch = nowEpoch
        con.execute("""insert into entityKey(entityFk, key, salt, keyTypeFk, algorithm,"""
                    """creationEpoch, expirationEpoch, lastUsedEpoch) values ("""
                    """(select primaryKey from entity where entityID=?),?,?,?,?,?,?,?)""",
                    (entityID, key, salt, keyTypeFk, algorithm, creationEpoch, expirationEpoch, lastUsedEpoch))
        log.info("Key saved to the database %s.", database)
        return True


def getKeyTypePk(keyType, database=None):
    """
    Return the `keyType` primary key per the key type description (string).

    Parameters
    ----------
    keyType : str
        `keyType` description.
    database : str
        filename of database. If `None`, an exception will be raised.

    Returns
    -------
    int
        `keyType` primary key.
    """
    # Check whether database was passed as argument.
    if database is None:
        # Exit immediately after logging error.
        log.error("Database filename is None. It must not be undefined.")
        raise SystemExit("Database filename is None. It must not be undefined.")

    con = sqlite3.connect(database)
    with con:
        return con.execute("select primaryKey from keyType where keyType=?", (keyType,)).fetchone()[0]

def dabeGlobalSetup(dabeObject, groupObject):
    """
    This function assists in performing the global parameter setup for a (dabe) Multi-authority ABE system.

    Basically, this function calls the distributed ABE object's setup() method, which should create a random
    group generator, and a random oracle (hash) function that maps GIDs to members in the group. The dabe_aw11
    class creates a hash function that always utilize the same group for mapping, but the random group
    generator should be same for all authorities in the dabe system.

    As such, what it is done is allow the creation of a random group generator and the hash random oracle for
    the dabe object upon calling setup(), but we then substitute the 'g' for the constant one defined
    in the constants module. Any instance of setup() call should use the function here instead, otherwise
    the keys, encryption and/or other cryptographic operations might fail because the wrong 'g' is utilized.

    Parameters
    ----------
    dabeObject : dabe object
        the DABE or hybrid DABE object which has the setup() function.
    groupObject : Pairing Group object
        Pairing Group object such that the pairingCurve type can be extracted.

    Returns
    -------
    dict
        The global parameters GP (with constant 'g'), a dictionary.
    """

    # Convert the JSON constant into dictionary such that we can merge/update it into GP.
    globalGroupGenerator = json.loads(constants.GLOBAL_GROUP_GENERATOR_JSON, cls=jsonhelper.KeyDecoder)
    # Consistency check: verify whether the PairingCurve in the 'g' constant is the same as the groupObject.
    if globalGroupGenerator['__pairingCurve__'] != groupObject.param:
        log.error("The constant global group generator g has different Pairing Curve type than the Group Object parameter.")
        log.error("    constant global group generator: %s; Group Object parameter: %s", constants.GLOBAL_GROUP_GENERATOR_JSON['__pairingCurve__'], groupObject.param)
        raise SystemExit("The constant global group generator g has different Pairing Curve type than the Group Object parameter.")
    # Call original setup() function.
    GP = dabeObject.setup()
    # Include the pairingCurve type for future use.
    GP.update({'__pairingCurve__':groupObject.param})
    #print("Original GP: ", GP)
    # Update the 'g' in the newly created GP.
    GP.update(globalGroupGenerator)
    # Let's see.
    #print("Updated GP: ", GP, "\nType: ", type(GP))


#    # Pop and save the hash mapping to include later.
#    print("GP as newly created: ", GP, "\nType: ", type(GP))
#    h = {'H':GP.pop('H')}
#    print(GP, "Type: ", type(GP))
#    # Convert to JSON.
#    GPJson = json.dumps(GP, cls=jsonhelper.KeyEncoder, pairingCurve=groupObj.param)
#    print("Original: ", GPJson, "\nType: ", type(GPJson))
#    # Substitute the random group generator g by the constant one.
#    GPJson.update(constants.GROUP_GENERATOR_JSON)
#    print("Updated: ", GPJson, "\nType: ", type(GPJson))
#    # Deserialize and re-insert the hash mapping.
#    GP = json.loads(GPJson, cls=jsonhelper.KeyDecoder)
#    print("GP before update: ", GP)
#    GP.update(h)
#    print("As pairing.Element: ", GP)
    return GP

# Create a function that creates and registers a TOTP only if there is no valid TOTP in the database.
# Create a function to expire TOTP.
# Create a function to retrieve TOTP from database and validate the current number. Retrieve only if valid.
# Create a function to retrieve if valid, or create if none.
def generateTotpRandomSecret(length=constants.RANDOM_SECRET_LENGTH_BITS):
    """
    Generate a random, base32-encoded string of 'length' length.

    Parameters
    ----------
    length : int, optional
        length of random string to generate, in bits, before base32 encoding. Default is 32 bytes or 256 bits.

    Returns
    -------
    str
        base32-encoded string.
    """

    # Generate random string of 'length' length and return base32-encoded string.
    #randomSecret = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
    return base64.b32encode(Crypto.Random.get_random_bytes(length//8))
    # Return base32-encoded string (the input must be utf-8-encoded).
    #return base64.b32encode(randomSecret.encode())

def generateNonce(length=constants.RANDOM_SECRET_LENGTH_BITS):
    """
    Generate a random, base64-encoded string of 'length' length.

    Parameters
    ----------
    length : int, optional
        length of random string to generate, in bits, before base64 encoding. Default is 32 bytes or 256 bits.

    Returns
    -------
    byte str
        base64-encoded string.
    """

    # Generate random string of 'length' length and return base64-encoded string.
    return base64.b64encode(Crypto.Random.get_random_bytes(length//8))

def createEntity(entityID, name, entityTypeFk, database, creationEpoch=None):
    """
    Creates an Entity in the database.

    Parameters
    ----------
    entityID : str
        entityID of the entity, unique, string.
    name : str
        string representing the name of the entity.
    entityTypeFk : int
        primary key of the entity type that identifies this entity.
    database : str
        filename of the database.
    creationEpoch : epoch, optional
        epoch time of creation of this entity. Default is None, which defaults to time.time()

    Returns
    -------
    bool
        **True** if insertion/creation was successful.
        **False** if insertion/creation failed due to integrity error (possibly duplicate entry).
    """

    if creationEpoch is None:
        creationEpoch = time.time()

    con = sqlite3.connect(database)
    with con:
        try:
            con.execute("insert into entity(entityID, name, entityTypeFk, creationEpoch) values (?,?,?,?)",
                        (entityID, name, entityTypeFk, creationEpoch))
            return True
        except sqlite3.IntegrityError:
            return False

def registerEntityAttribute(entityID, attribute,
                          creationEpoch=None, expirationEpoch=None, lastUpdatedEpoch=None, database=None):
    """
    Registers an entity attribute.
    Note that if the entity already has the attribute, then the `expirationEpoch` will be updated with the one
    passed as argument, regardless of whether the new occurs after or before the one in the database.

    Parameters
    ----------
    entityID : str
        ID of the entity who owns the attribute.
    attribute : str
        attribute string of the entity to be registered to the database. It must previously exist in attribute table.
    creationEpoch : epoch, optional
        epoch when the key was registered to the database.
    expirationEpoch : epoch, optional
        epoch of the expiration date of this attribute.
    lastUpdatedEpoch : epoch, optional
        epoch at which the attribute was last updated (basically, when the expirationEpoch was last altered).
    database : str
        filename of database. If `None`, an exception will be raised.

    Returns
    -------
    bool
        **True** if entity attributes did not exist previously, and therefore the ones passed were successfully registered.
        **False** if entity attributes existed previously. In this case, only the expirationEpoch will be (were) updated.

    Notes
    -----
    Note that if the entity already has the attribute, then the expirationEpoch will be updated with the one
    passed as argument, regardless of whether the new occurs after or before the one in the database.

    Also note that ABE keys are tied to attributes. In case an attribute "expires", the code should make sure the
    respective ABE keys also expire, otherwise we would have an inconsistency. Since the expiration comes passively
    from the expirationEpoch, perhaps we should have a "watchdog" function that periodically scans for ABE keys whose
    attributes are no longer valid (either fetching all keys and verifying the attributes, or fetching expired attributes
    and then checking for still valid keys).
    """

    nowEpoch = time.time()
    # We can use the "INSERT OR REPLACE" construction here instead of SELECT to verify existence
    # and then decide whether to insert or update.
    # http://stackoverflow.com/questions/418898/sqlite-upsert-not-insert-or-replace

    # Verify whether same entry already exists in database.
    con = sqlite3.connect(database)
    with con:
        #attrPrimaryKey = con.execute("select primaryKey from attribute where attribute=?", (attribute,)).fetchall()
        #attrPrimaryKey = attrPrimaryKey[0][0]
        result = con.execute("""select * from entityAttribute where """
                             """entityFk= (select primaryKey from entity where entityID=?) and """
                             """attributeFk= (select primaryKey from attribute where attribute=?)""",
                             (entityID, attribute)).fetchall()
        # If something was found, then just update the expirationEpoch with the new one.
        # Define lastUpdatedEpoch as current time if no value as passed as argument.
        # Define creationEpoch to current time if values were not passed as arguments.
        if creationEpoch is None:
            creationEpoch = nowEpoch # Only used if creating new attributes, not updating.
        if lastUpdatedEpoch is None:
            lastUpdatedEpoch = nowEpoch
        if result:
            con.execute("""update entityAttribute """
                        """set expirationEpoch=?, lastUpdatedEpoch=?"""
                        """where entityFk= (select primaryKey from entity where entityID=?) and """
                        """attributeFk= (select primaryKey from attribute where attribute=?)""",
                        (expirationEpoch, lastUpdatedEpoch, entityID, attribute))
            return False # Done updating.
        else:
            # Record does not exist. Insert.
            con.execute("""insert into entityAttribute(entityFk, attributeFk, creationEpoch, expirationEpoch, lastUpdatedEpoch) """
                        """values ((select primaryKey from entity where entityID=?),"""
                        """(select primaryKey from attribute where attribute=?),"""
                        """?,?,?)""", (entityID, attribute, creationEpoch, expirationEpoch, lastUpdatedEpoch))
            return True # Done inserting.

def getAllAttributesIntersectionTwoEntities(entityIDone, entityIDtwo, notExpiredBeforeEpoch=None, database=None):
    """
    Retrieves all attributes registered (in the database) to entityIDone, all attributes registered to entityIDtwo,
    and returns a (possibly empty) list containing the intersection of attributes of the two sets (i.e., all attributes registered
    to entityIDone that are also registered to entityIDtwo). Only valid attributes are considered.

    The corresponding table in the database should be entityAttribute.

    The typical usage of this function is to find the list of attributes registered to one user that belong to one
    specific authority. Therefore, it is the intersection of the set of attributes belonging to the user and the set
    of attributes belonging to the authority.

    Parameters
    ----------
    entityIDone : str
        entityID of one entity for fetching all of its registered attributes.
    entityIDtwo : str
        entityID of the other entity for fetching all of its registered attributes.
    notExpiredBeforeEpoch : epoch, optional
        attributes will be retrieved if their `expirationEpoch` is equal or greater then `notExpiredBeforeEpoch`.
    database : str
        filename of database. If `None`, an exception will be raised.

    Returns
    -------
    list of str
        list of attributes registered to entityIDone that are also registered to entityIDtwo.
    """

    attributesEntityOne = getAllEntityAttributes(entityIDone, notExpiredBeforeEpoch=notExpiredBeforeEpoch, database=database)
    attributesEntityTwo = getAllEntityAttributes(entityIDtwo, notExpiredBeforeEpoch=notExpiredBeforeEpoch, database=database)
    # Perform intersection by making sets out of the lists of attributes, and transform the resulting set into a list.
    return list(set(attributesEntityOne) & set(attributesEntityTwo))


def getAllEntityAttributes(entityID, notExpiredBeforeEpoch=None, database=None):
    """
    Retrieves all entity attributes from database with `expirationEpoch` on or after `notExpiredBeforeEpoch`, i.e.,
    that are not expired before `notExpiredBeforeEpoch`.

    Parameters
    ----------
    entityID: str
        ID of the entity who owns the attributes.
    notExpiredBeforeEpoch : epoch, optional
        attributes will be retrieved if their `expirationEpoch` is equal or greater then `notExpiredBeforeEpoch`.
    database : str
        filename of database. If `None`, an exception will be raised.

    Returns
    -------
    list of str
        List of unique entity attributes, wherein each element is a string.
    """

    nowEpoch = time.time()

    # If not specified, set notExpiredBeforeEpoch to this instant.
    if notExpiredBeforeEpoch is None:
        notExpiredBeforeEpoch = nowEpoch

    con = sqlite3.connect(database)
    with con:
        # Get the attributes for the entity that have not expired.
        entityAttributes = con.execute("""select attribute from attribute join entityAttribute on attribute.primaryKey == entityAttribute.attributeFk """
                                     """where entityFk= """
                                     """(select primaryKey from entity where entityID=?) and """
                                     """expirationEpoch>=?""", (entityID,notExpiredBeforeEpoch)).fetchall()

    # This is one way to extract the results from the list of tuples.
    # Each tuple in the list of tuples is composed by the result we want, and a null element (a tuple of one element, in effect).
    # Zip the list of tuples into a big list (which will result into a list of single elements,
    # since the second element in each tuple is null), use next to read the iterator (created by zip),
    # and then convert into a list.
    return [element[0] for element in entityAttributes]

def getAllLikeAttributes(searchString, database=None):
    """
    Retrieves all attributes that match a certain search string.

    Typically, this function will be utilized to retrieve all attributes belonging to an authority, such
    as all attributes beginning with "amazon.*".

    Parameters
    ----------
    searchString : str
        search string or pattern to which the attributes in the database will be compared.
    database : str
        filename of the database file. If `None`, an exception will be raised.

    Returns
    -------
    List of str
        List of attributes, wherein each element is a string matching the searchString.
    """

    con = sqlite3.connect(database)
    with con:
        # Get the attributes matching the searchString.
        attributes = con.execute("select attribute from attribute where attribute like ?", (searchString,)).fetchall()

    # Let's use a list comprehension to extract the relevant results from the list of tuples.
    return [element[0] for element in attributes]


def getAllLikeEntityIDs(searchString, database=None):
    """
    Retrieves all entities whose entityID match a certain search string.

    For instance, get all entities that contain the string "amazon%" or ".com" in the entityID.

    Parameters
    ----------
    searchString : str
        search string or pattern to which the entityIDs in the database will be compared.
    database : str
        filename of the database file. If `None`, an exception will be raised.

    Returns
    -------
    List of str
        List of entityIDs, wherein each element is a string matching the searchString.
    """

    con = sqlite3.connect(database)
    with con:
        # Get the entities whose name matches the searchString.
        entities = con.execute("select entityID from entity where entityID like ?", (searchString,)).fetchall()

    # Let's use a list comprehension to extract the relevant results from the list of tuples.
    return [element[0] for element in entities]


def createAttribute(attribute, database):
    """
    Creates an attribute in the database.

    Parameters
    ----------
    attribute : str
        name of the attribute, unique string.
    database : str
        filename of the database.

    Returns
    -------
    **True** if insertion/creation was successful.
    **False** if insertion/creation failed due to integrity error (possibly duplicate entry).
    """

    con = sqlite3.connect(database)
    with con:
        try:
            con.execute("insert into attribute(attribute) values (?)", (attribute,))
            return True
        except sqlite3.IntegrityError:
            return False

def expireKeysOfType(entityID, keyTypeList, notExpiredBeforeEpoch=None, lastUsedEpoch=None, database=None):
    """
    Expires existing, valid, keys of a specific type belonging to entityID.

    The function will search for the keys of specific types which `expirationEpoch` is greater than
    `notExpiredBeforeEpoch`. If found, the function will update that field (`expirationEpoch`) with the value of
    `notExpiredBeforeEpoch`, and also update `lastUsedEpoch` field with the parameter value or `time.time()` if not
    specified.

    Therefore, the function will not extend expiration epoch of keys, but only update `expirationEpoch` to
    lower values than current ones.

    Parameters
    ----------
    entityID : str
        ID of the entity owner of the keys.
    keyTypeList : list of str
        List (possibly of one element) with type of keys (descriptive string) or a single key, according to `constants.py`. Should match exactly what is found in the database.
        Note that the function will iterate through each value within keyType and accumulate the updated tuples.
    notExpiredBeforeEpoch : epoch, optional
        keys will be retrieved if their `expirationEpoch` is greater than `notExpiredBeforeEpoch`.
        If `None`, `time.time()` will be utilized.
    lastUsedEpoch : epoch, optional
        the epoch of the recording. Default is None, which will then utilize the current epoch. This is an epoch float.
    database : str
        filename of database. If `None`, an exception will be raised.

    Returns
    -------
    int
        Number of rows updated (i.e., keys expired).
    """

    nowEpoch = time.time()

    if notExpiredBeforeEpoch is None:
        notExpiredBeforeEpoch = nowEpoch

    if lastUsedEpoch is None:
        lastUsedEpoch = nowEpoch

    con = sqlite3.connect(database)
    # To expire, set expirationEpoch to notExpiredBeforeEpoch (typically time.time()).
    # We will iterate through each element of keyType, perform the update, and accumulate the number of changes to return this value.
    with con:
        for keyTypeElement in keyTypeList:
#            con.execute("""update entityKey """
#                        """set expirationEpoch=?, lastUsedEpoch=? """
#                        """where entityFk=(select primaryKey from entity where entityID=?) and """
#                        """keyTypeFk = (select primaryKey from keyType where keyType=?) and """
#                        """expirationEpoch > ?""", (notExpiredBeforeEpoch, lastUsedEpoch, entityID, keyTypeElement, notExpiredBeforeEpoch))
            con.execute("""update entityKey """
                        """set expirationEpoch=:notExpiredBeforeEpoch, lastUsedEpoch=:lastUsedEpoch """
                        """where entityFk=(select primaryKey from entity where entityID=:entityID) and """
                        """keyTypeFk = (select primaryKey from keyType where keyType=:keyTypeElement) and """
                        """expirationEpoch > :notExpiredBeforeEpoch""", {"notExpiredBeforeEpoch":notExpiredBeforeEpoch,
                                                                         "lastUsedEpoch":lastUsedEpoch,
                                                                         "entityID":entityID,
                                                                         "keyTypeElement":keyTypeElement})

        return con.total_changes

def prorogueKeysOfType(entityID, keyType, newExpirationEpoch=None, lastUsedEpoch=None, database=None):
    """
    Extend or postpone expirationEpoch of existing keys of specific type(s), if their expirationEpoch is greater than time.time() (i.e., the
    keys are still valid). We will not postpone expiration of already expired keys, lest creating "zombies".


    Note: Should we only allow prorogation, or actually updating the expirationEpoch to a lower value than
    the original?

    Parameters
    ----------
    entityID : str
        ID of the entity owner of the keys.
    keyType : list of str
        List (possibly of one element) with type of keys (descriptive string) or a single key, according to `constants.py`. Should match exactly what is found in the database.
        Note that the function will iterate through each value within keyType and accumulate the updated tuples.
    newExpirationEpoch : epoch, optional
        new expiration epoch for valid keys.
    lastUsedEpoch : epoch, optional
        the epoch of the updating. If `None`, use time.time().
    database : str
        filename of authority database. If `None`, an exception will be raised.

    Returns
    -------
    int
        Number of key tuples with `expirationEpoch` postponed.

    Notes
    -----
    Should we only allow prorogation, or actually updating the expirationEpoch to a lower value than
    the original?
    """

    nowEpoch = time.time()
    # Return immediately in the case below. There has to be a newExpirationEpoch.
    if newExpirationEpoch is None:
        return 0

    if lastUsedEpoch is None:
        lastUsedEpoch = nowEpoch

    con = sqlite3.connect(database)
    # To prorogue, set expirationEpoch to newExpirationEpoch if newExpirationEpoch > expirationEpoch AND
    # expirationEpoch > time.time() (i.e., key is still valid, not expired).
    # Iterate through each keyType within keyType.
    with con:
        for keyTypeElement in keyType:
#            con.execute("""update entityKey """
#                        """set expirationEpoch=?, lastUsedEpoch=? """
#                        """where entityFk=(select primaryKey from entity where entityID=?) and """
#                        """keyTypeFk in (select primaryKey from keyType where keyType=?) and """
#                        """expirationEpoch > ? and expirationEpoch < ?""",
#                        (newExpirationEpoch, lastUsedEpoch, entityID, keyTypeElement, nowEpoch, newExpirationEpoch))
            con.execute("""update entityKey """
                        """set expirationEpoch=:newExpirationEpoch, lastUsedEpoch=:lastUsedEpoch """
                        """where entityFk=(select primaryKey from entity where entityID=:entityID) and """
                        """keyTypeFk in (select primaryKey from keyType where keyType=:keyTypeElement) and """
                        """expirationEpoch > :nowEpoch and expirationEpoch < :newExpirationEpoch""",
                        {"newExpirationEpoch":newExpirationEpoch,
                         "lastUsedEpoch":lastUsedEpoch,
                         "entityID":entityID,
                         "keyTypeElement":keyTypeElement,
                         "nowEpoch":nowEpoch})
        return con.total_changes


def getEntityKeysOfType(entityID, keyType, notExpiredBeforeEpoch=None, lastUsedEpoch=None, database=None):
    """
    Return existing and valid entity keys from the database of specific keyType.

    If there are valid, existing keys in the database (i.e., keys from which the expirationEpoch is greater than
    the expirationEpoch as parameter) of specified keyType, then return them. Otherwise, return an empty list.

    Parameters
    ----------
    entityID : str
        ID of the entity owner of the keys.
    keyType : str
        Key Type of key to retrieve (string). Only one type (not a list of types) is supported.
    notExpiredBeforeEpoch : epoch, optional
        keys will be retrieved if their `expirationEpoch` is greater than `notExpiredBeforeEpoch`.
        If `None`, `time.time()` will be utilized.
    lastUsedEpoch : epoch, optional
        the epoch of the updating. If `None`, use time.time().
    database : str
        filename of authority database. If `None`, an exception will be raised.

    Returns
    -------
    list of byte str
        A list of keys retrieved from the database, if valid ones were found. It can be an empty list if no keys were found.
        The list is ordered ascendingly by expirationEpoch.

    Notes
    -----
    The lastUsedEpoch is updated *after* the rows are retrieved. In this function, wherein only the keys are returned,
    this behavior is of little consequence.
    """

    nowEpoch = time.time()
    if notExpiredBeforeEpoch is None:
        notExpiredBeforeEpoch = nowEpoch
    if lastUsedEpoch is None:
        lastUsedEpoch = nowEpoch

    con = sqlite3.connect(database)
    with con:
        # Retrieve entity keys if any (valid ones). Also retrieve primaryKey such that we can update lastUsedEpoch later.
        storedKeys = con.execute("""select primaryKey, key from entityKey where """
                             """entityFk=(select primaryKey from entity where entityID=?) and """
                             """keyTypeFk in (select primaryKey from keyType where keyType=?) and """
                             """expirationEpoch > ? order by expirationEpoch""",
                             (entityID, keyType, notExpiredBeforeEpoch)).fetchall() # The expirationEpoch > time.time() here will fetch non-expired entries.
    # Now reconstruct the list of tuples into a list of values (or empty list). Construct a list of keys and a list of primaryKey.
    keysList = []
    primaryKeyList = []
    for tupleInList in storedKeys:
        primaryKeyList.append(tupleInList[0])
        keysList.append(tupleInList[1])
    # Update the lastUsedEpoch to reflect the last time a key was touched in the database.
    # Construct a "placeHolders" string wherein there are one ? per element in primaryKeyList.
    placeHolders = _constructPlaceHolder(primaryKeyList)
    query = "update entityKey set lastUsedEpoch = ? where primaryKey in %s" % placeHolders
    with con:
        con.execute(query, [lastUsedEpoch] + primaryKeyList)
        # Sanity check.
        if con.total_changes != len(keysList):
            log.error("Sanity check failed. Updated number of rows (for lastUsedEpoch) different from retrieved rows.")
            raise SystemExit("Sanity check failed. Updated number of rows (for lastUsedEpoch) different from retrieved rows.")

    # Done.
    return keysList


def mergeListOfJsonObjectsIntoOneDictionaryAndDeserialize(listOfJsonObjects):
    """
    Given a list of JSON objects, this function will merge all of them into one dictionary wherein serialized objects were deserialized.

    Parameters
    ----------
    listOfJsonObjects : list of str
        a list of individual JSON objects.

    Returns
    -------
    dict
        One (possible empty) dict representing the dictionary resulting of merging all deserialized elements of the given list.
    """
    return json.loads(mergeListOfJsonObjectsIntoOneJson(listOfJsonObjects), cls=jsonhelper.KeyDecoder)

def mergeListOfJsonObjectsIntoOneJson(listOfJsonObjects):
    """
    Given a list of JSON objects, this function will merge all of them into one dictionary and return the JSON representation of it.

    Parameters
    ----------
    listOfJsonObjects : list of str
        a list of individual JSON objects.

    Returns
    -------
    str
        One (possible empty) JSON string representing the dictionary resulting of merging all elements of the given list.
    """
    returnedDict = mergeListOfJsonObjectsIntoOneDictionary(listOfJsonObjects)
#    # If we have an empty dictionary, do not serialize it. JSON converts an empty dict into "{}", we do not want that.
#    # We rather have an empty string.
#    if not returnedDict: # == {}
#        return ""
#    else:
#        return json.dumps(returnedDict)
    return json.dumps(returnedDict)

def mergeListOfJsonObjectsIntoOneDictionary(listOfJsonObjects):
    """
    Given a list of JSON objects, this function will merge all of them into one dictionary and return it.

    Typical use case is a list of ABE keys (which are dictionaries) as JSON representations, resulting from a select from a database (there might be the case in which
    an entity has several ABE key dictionaries, instead of one huge dictionary will all keys, e.g., one dictionary per ABE secret key per ABE authority).
    We want not the list of dictionaries, but one big dictionary that we can feed an ABE decryption function.

    Parameters
    ----------
    listOfJsonObjects : list of str
        a list of individual JSON objects.

    Returns
    -------
    dict
        One (possible empty) dict representing the dictionary resulting of merging all elements of the given list.
    """

    mergedDictionary = {}
#    # If listOfDictionaries is empty, just return an empty dict.
#    if not listOfJsonObjects:
#        return {}

    for element in listOfJsonObjects:
        mergedDictionary.update(ast.literal_eval(element)) # Use ast.literal_eval because the elements are the string representation of dictionaries (JSON format).
    # Revert the final dictionary to the string representation of it, such that it can be deserialized by JSON.
    # Cannot simply convert mergedDictionary to string using str, because if mergedDictionary is an empty dictionary ({}), then
    # the result of str({}) will be '{}', which is NOT an empty string and will break things ahead.
    # There is a solution posted here: http://stackoverflow.com/questions/35389648/convert-empty-dictionary-to-empty-string/35389716.
    # The problem is that the resulting string will contain single quotes, and subsequent JSON deserializations will
    # fail, since JSON wants double quotes.
    # Then, a simpler solution, which will properly use double quotes, is use json.dumps. Since the input
    # dictionary (mergedDictionary) has already been serialized before, there is no need for complicated conversions
    # (encoder/decoder). A simple json.dumps will work.
    # But, in addition, the input dictionary cannot simplyt be empty, which will again result in the '{}' string.
    # Then, just test for an empty listOfDictionaries in the beginning and return immediately with an empty string if
    # such is the case.
    return mergedDictionary


def convertJsonIntoListOfSingletonJson(jsonObject, pairingGroup=constants.DEFAULT_PAIRING_GROUP):
    """
    Given a JSON object, this function will separate each key-value pair within the original JSON object into its own JSON
    object (i.e., a singleton JSON), returning a list of such JSON singletons.

    The primary goal of this function was to have a set of ABE keys for a user (one key is a key-value pair) and separate that
    set into singleton key-value pairs (attribute-secret key pairs), such that each attribute-secret key pair would go into
    its own SQLite database record. This way, each attribute-secret key can be more easily manipulated with regards to
    expiration epoch, etc. It is important to note that, for a set of user ABE keys using decentralized ABE, the set of secret
    keys generated by Charm Crypto do include the gid (the entityID, in this framework). As such, we must purge the gid before
    storing the individual key-value pairs into the database.

    The gid *must* be in the dictionary when calling the decrypt function in the ABE module.

    Parameters
    ----------
    jsonObject : str
        JSON object in the form of a JSON string.

    Returns
    -------
    list of JSON str
        One possibly empty list of JSON (str) objects, each of which is a singleton.

    Notes
    -----
    Only one type of Pairing Group object is supported in this function. If the key-value elements within the JSON object
    have different types of Pairing Group parameter, then this function will not work properly.
    """
    # If listOfDictionaries is empty, just return an empty string.
    #if not listOfDictionaries:
    #    return ""

    jsonAsDict = json.loads(jsonObject, cls=jsonhelper.KeyDecoder)
    # Now separate the key-value pairs within the dict into a list of singletons.
    listOfJson = []
    # Such that we can extract the Pairing Curve.
    groupObject = PairingGroup(pairingGroup)
    for key, value in jsonAsDict.items():
        listOfJson.append(json.dumps({key:value}, cls=jsonhelper.KeyEncoder, pairingCurve=groupObject.param))
    return listOfJson


def _constructPlaceHolder(values):
    """
    This function constructs a variable-size placeholder string of '?' for use of SQL.

    This function needs to be tightly controlled for security purposes.

    Parameters
    ----------
    values : list or tuple of str (?)
        the list or tuple of values needing placeholders.

    Returns
    -------
    str
        string of (?, ?, ... , ?), wherein the number of ? is the len(values).
    """
    return '({})'.format(', '.join('?' * len(values)))

def registerTotpLocatheSecretSeedToDatabase(entityID, secretSeed,
                          creationEpoch=None, expirationEpoch=None, lastUsedEpoch=None, database=None):
    """
    Registers a TOTP (LOCATHE) secret seed for a specific `entityID` to the specified database, including the proper epochs if desired.
    If there is a TOTP entry with the same `entityID`,
    and still valid (i.e., `expirationEpoch` greater than time.time()), the function returns **False**, otherwise returns **True**.
    Note that this TOTP keyType is exclusively for use within the LOCATHE protocol, i.e., the LOCATHE protocol computes this TOTP,
    instead of its value being provided Out-Of-Band.

    Parameters
    -----------
    entityID : str
        ID of the entity who owns the TOTP secret seed as string.
    secretSeed : base32-encoded byte str
        secret TOTP seed to record to the database, as base32-encoded byte string.
    creationEpoch : epoch, optional
        epoch when the key was registered to the database.
    expirationEpoch : epoch, optional
        epoch of the expiration date of this key.
    lastUsedEpoch : epoch, optional
        the epoch of the recording. Default is None, which will then utilize the current epoch. This is an epoch float.
    database : str
        filename of database. If `None`, an exception will be raised.

    Returns
    -------
    bool
        **True** if the registration was successful; **False** a valid TOTP already exists for entityID.

    Notes
    -----
    Note that this TOTP keyType is exclusively for use within the LOCATHE protocol, i.e., the LOCATHE protocol computes this TOTP,
    instead of its value being provided Out-Of-Band.
    """

    nowEpoch = time.time()
    # Check whether database was passed as argument.
    if database is None:
        # Exit immediately after logging error.
        log.error("Database filename is None. It must not be undefined.")
        raise SystemExit("Database filename is None. It must not be undefined.")

    keyType = constants.TOTP_SEED_LOCATHE_KEY_TYPE
    # Must test here for uniqueness of TOTP for entityID, if that is the intent purpose of TOTP.
    existingTotpSeeds = getEntityKeysOfType(entityID, constants.TOTP_SEED_LOCATHE_KEY_TYPE, notExpiredBeforeEpoch=nowEpoch, database=database)
    # If there is more than one existing TOTP seeds, log that and return.
    if len(existingTotpSeeds) > 1:
        log.error("Consistency error: there are %s valid TOTP secret seeds in the database; there should be only one.", len(existingTotpSeeds))
        return False
    # There is exactly one valid TOTP key. Not an error, but return immediately.
    if len(existingTotpSeeds) == 1:
        log.info("There is already a valid TOTP secret seed in the database. Nothing was registered.")
        return False

    # There are no valid TOTP seeds in the database. OK to register the newly created one.
    return registerKeyToDatabase(entityID, secretSeed, None, keyType, "TOTP", creationEpoch=creationEpoch, expirationEpoch=expirationEpoch, lastUsedEpoch=lastUsedEpoch, database=database)

def expireTotpLocatheSecretSeeds(entityID, notExpiredBeforeEpoch=None, lastUsedEpoch=None, database=None):
    """
    Expires existing, valid, TOTP LOCATHE secret seeds from an entityID.
    Note that this TOTP keyType is exclusively for use within the LOCATHE protocol, i.e., the LOCATHE protocol computes this TOTP,
    instead of its value being provided Out-Of-Band.

    The function will search for the TOTP keys for which `expirationEpoch` is greater than
    `notExpiredBeforeEpoch`. If found, the function will update that field (`expirationEpoch`) with the value of
    `notExpiredBeforeEpoch`, and also update `lastUsedEpoch` field with the parameter value or `time.time()` if not
    specified.

    Therefore, the function will not extend expiration epoch of TOTP keys, but only update `expirationEpoch` to
    lower values than current ones.

    Parameters
    ----------
    entityID : str
        ID of the entity owner of the keys.
    notExpiredBeforeEpoch : epoch, optional
        keys will be retrieved if their `expirationEpoch` is greater than `notExpiredBeforeEpoch`.
        If `None`, `time.time()` will be utilized.
    lastUsedEpoch : epoch, optional
        the epoch of the recording. Default is None, which will then utilize the current epoch. This is an epoch float.
    database : str
        filename of database. If `None`, an exception will be raised.

    Returns
    -------
    int
        Number of rows updated (i.e., keys expired).

    Notes
    -----
    There should be only one valid TOTP seed for an entityID, but this function will remain agnostic for this and will expire
    one or more valid TOTP seeds.

    Note that this TOTP keyType is exclusively for use within the LOCATHE protocol, i.e., the LOCATHE protocol computes this TOTP,
    instead of its value being provided Out-Of-Band.

    """

    numberOfExpiredKeys = expireKeysOfType(entityID, [constants.TOTP_SEED_LOCATHE_KEY_TYPE], notExpiredBeforeEpoch=notExpiredBeforeEpoch,
                            lastUsedEpoch=lastUsedEpoch, database=database)
    log.info("TOTP seeds expired for entity %s: %s.", entityID, numberOfExpiredKeys)
    return numberOfExpiredKeys


def getEntityCurrentTotpLocatheToken(entityID, tokenLength=constants.TOTP_TOKEN_LENGTH_DIGITS,
                              validityInterval=constants.TOTP_VALIDITY_INTERVAL_SECONDS, database=None):
    """
    Generates and gets the entity's current TOTP LOCATHE token per current time.time(), registered secret seed in the database,
    validity interval, and token length.
    Note that this TOTP keyType is exclusively for use within the LOCATHE protocol, i.e., the LOCATHE protocol computes this TOTP,
    instead of its value being provided Out-Of-Band.

    This function will retrieve the entity's secret seed in the database, generate the respective TOTP token, and return it.
    If no valid (non-expired) secret seed is found, the function returns None.

    Parameters
    ----------
    entityID : str
        entityID that owns the secret TOTP seed.
    tokenLength : int, optional
        Length, in digits (as int), of the TOTP token to generate and return.
    validityInterval : int, optional
        Time interval of validity, in seconds, of a generated TOTP token. At each validity interval slot, a new TOTP token
        is generated and is therefore valid. Hence, each validity slot has a correspondent TOTP token per the secret seed.
    database : str
        Filename of the SQLite database.

    Returns
    -------
    Number or None
        The generated token per the parameters. If no valid secret seed was found for the entityID, then None is returned.

    Notes
    -----
    Note that this TOTP keyType is exclusively for use within the LOCATHE protocol, i.e., the LOCATHE protocol computes this TOTP,
    instead of its value being provided Out-Of-Band.
    """

    # Fetch the entity's TOTP seed from the database if valid now.
    secretSeedList = getEntityKeysOfType(entityID, constants.TOTP_SEED_LOCATHE_KEY_TYPE, notExpiredBeforeEpoch=time.time(),
                                     database=database)
    # At the present implementation, there should be at most one TOTP secret per user in the database. Assert this here.
    # If more than one valid TOTP seed found, log and exit with exception.
    if len(secretSeedList) > 1:
        log.error("Consistency violation: a total of %s valid TOTP seeds were found for entity %s in database %s.", len(secretSeedList),
                  entityID, database)
        raise SystemExit("Consistency violation: more than one valid TOTP seeds found in database!")

    # If the list of returned keys is empty, then return None.
    if len(secretSeedList) == 0:
        log.info("No TOTP seed found in the database %s for entity %s.", database, entityID)
        return None
    # Otherwise, fetch the seed from the one-item seed.
    secretSeed = secretSeedList[0]
    # Generate a TOTP token with the secret seed and return it.
    return onetimepass.get_totp(secretSeed, token_length=tokenLength, interval_length=validityInterval)

def registerTotpOOBSecretSeedToDatabase(entityID, secretSeed,
                          creationEpoch=None, expirationEpoch=None, lastUsedEpoch=None, database=None):
    """
    Registers a TOTP secret seed for a specific `entityID` to the specified database, including the proper epochs if desired.
    If there is a TOTP entry with the same `entityID`,
    and still valid (i.e., `expirationEpoch` greater than time.time()), the function returns **False**, otherwise returns **True**.

    Parameters
    -----------
    entityID : str
        ID of the entity who owns the TOTP secret seed as string.
    secretSeed : base32-encoded byte str
        secret TOTP seed to record to the database, as base32-encoded byte string.
    creationEpoch : epoch, optional
        epoch when the key was registered to the database.
    expirationEpoch : epoch, optional
        epoch of the expiration date of this key.
    lastUsedEpoch : epoch, optional
        the epoch of the recording. Default is None, which will then utilize the current epoch. This is an epoch float.
    database : str
        filename of database. If `None`, an exception will be raised.

    Returns
    -------
    bool
        **True** if the registration was successful; **False** a valid TOTP already exists for entityID.

    Notes
    -----
    The function operates exclusively on Out-Of-Band TOTP, for OOB TOTP keyType. The TOTP computed automatically by LOCATHE protocol
    is another keyType and specific functions are provided for that TOTP LOCATHE.
    """

    nowEpoch = time.time()
    # Check whether database was passed as argument.
    if database is None:
        # Exit immediately after logging error.
        log.error("Database filename is None. It must not be undefined.")
        raise SystemExit("Database filename is None. It must not be undefined.")

    keyType = constants.TOTP_SEED_LOCATHE_KEY_TYPE
    # Must test here for uniqueness of TOTP for entityID, if that is the intent purpose of TOTP.
    existingTotpSeeds = getEntityKeysOfType(entityID, constants.TOTP_SEED_LOCATHE_KEY_TYPE, notExpiredBeforeEpoch=nowEpoch, database=database)
    # If there is more than one existing TOTP seeds, log that and return.
    if len(existingTotpSeeds) > 1:
        log.error("Consistency error: there are %s valid TOTP secret seeds in the database; there should be only one.", len(existingTotpSeeds))
        return False
    # There is exactly one valid TOTP key. Not an error, but return immediately.
    if len(existingTotpSeeds) == 1:
        log.info("There is already a valid TOTP secret seed in the database. Nothing was registered.")
        return False

    # There are no valid TOTP seeds in the database. OK to register the newly created one.
    return registerKeyToDatabase(entityID, secretSeed, None, keyType, "TOTP", creationEpoch=creationEpoch, expirationEpoch=expirationEpoch, lastUsedEpoch=lastUsedEpoch, database=database)

def expireTotpOOBSecretSeeds(entityID, notExpiredBeforeEpoch=None, lastUsedEpoch=None, database=None):
    """
    Expires existing, valid, TOTP secret seeds from an entityID.

    The function will search for the TOTP keys for which `expirationEpoch` is greater than
    `notExpiredBeforeEpoch`. If found, the function will update that field (`expirationEpoch`) with the value of
    `notExpiredBeforeEpoch`, and also update `lastUsedEpoch` field with the parameter value or `time.time()` if not
    specified.

    Therefore, the function will not extend expiration epoch of TOTP keys, but only update `expirationEpoch` to
    lower values than current ones.

    Parameters
    ----------
    entityID : str
        ID of the entity owner of the keys.
    notExpiredBeforeEpoch : epoch, optional
        keys will be retrieved if their `expirationEpoch` is greater than `notExpiredBeforeEpoch`.
        If `None`, `time.time()` will be utilized.
    lastUsedEpoch : epoch, optional
        the epoch of the recording. Default is None, which will then utilize the current epoch. This is an epoch float.
    database : str
        filename of database. If `None`, an exception will be raised.

    Returns
    -------
    int
        Number of rows updated (i.e., keys expired).

    Notes
    -----
    There should be only one valid TOTP seed for an entityID, but this function will remain agnostic for this and will expire
    one or more valid TOTP seeds.

    The function operates exclusively on Out-Of-Band TOTP, for OOB TOTP keyType. The TOTP computed automatically by LOCATHE protocol
    is another keyType and specific functions are provided for that TOTP LOCATHE.
    """

    numberOfExpiredKeys = expireKeysOfType(entityID, [constants.TOTP_SEED_LOCATHE_KEY_TYPE], notExpiredBeforeEpoch=notExpiredBeforeEpoch,
                            lastUsedEpoch=lastUsedEpoch, database=database)
    log.info("TOTP seeds expired for entity %s: %s.", entityID, numberOfExpiredKeys)
    return numberOfExpiredKeys


def getEntityCurrentTotpOOBToken(entityID, tokenLength=constants.TOTP_TOKEN_LENGTH_DIGITS,
                              validityInterval=constants.TOTP_VALIDITY_INTERVAL_SECONDS, database=None):
    """
    Generates and gets the entity's current TOTP token per current time.time(), registered secret seed in the database,
    validity interval, and token length.

    This function will retrieve the entity's secret seed in the database, generate the respective TOTP token, and return it.
    If no valid (non-expired) secret seed is found, the function returns None.

    Parameters
    ----------
    entityID : str
        entityID that owns the secret TOTP seed.
    tokenLength : int, optional
        Length, in digits (as int), of the TOTP token to generate and return.
    validityInterval : int, optional
        Time interval of validity, in seconds, of a generated TOTP token. At each validity interval slot, a new TOTP token
        is generated and is therefore valid. Hence, each validity slot has a correspondent TOTP token per the secret seed.
    database : str
        Filename of the SQLite database.

    Returns
    -------
    Number or None
        The generated token per the parameters. If no valid secret seed was found for the entityID, then None is returned.

    Notes
    -----
    The function operates exclusively on Out-Of-Band TOTP, for OOB TOTP keyType. The TOTP computed automatically by LOCATHE protocol
    is another keyType and specific functions are provided for that TOTP LOCATHE.
    """

    # Fetch the entity's TOTP seed from the database if valid now.
    secretSeedList = getEntityKeysOfType(entityID, constants.TOTP_SEED_LOCATHE_KEY_TYPE, notExpiredBeforeEpoch=time.time(),
                                     database=database)
    # At the present implementation, there should be at most one TOTP secret per user in the database. Assert this here.
    # If more than one valid TOTP seed found, log and exit with exception.
    if len(secretSeedList) > 1:
        log.error("Consistency violation: a total of %s valid TOTP seeds were found for entity %s in database %s.", len(secretSeedList),
                  entityID, database)
        raise SystemExit("Consistency violation: more than one valid TOTP seeds found in database!")

    # If the list of returned keys is empty, then return None.
    if len(secretSeedList) == 0:
        log.info("No TOTP seed found in the database %s for entity %s.", database, entityID)
        return None
    # Otherwise, fetch the seed from the one-item seed.
    secretSeed = secretSeedList[0]
    # Generate a TOTP token with the secret seed and return it.
    return onetimepass.get_totp(secretSeed, token_length=tokenLength, interval_length=validityInterval)

def getEntityKeysOfTypeWholeTuple(entityID, keyType, notExpiredBeforeEpoch=None, lastUsedEpoch=None, database=None):
    """
    Return tuples as sqlite3.Row objects from entityKey table from the database, wherein the keys are existing and valid.

    If there are valid, existing keys in the database (i.e., keys from which the expirationEpoch is greater than
    the expirationEpoch as parameter) of specified keyType, then return the entire respective tuples converted to
    a list of sqlite3.Row objects. Otherwise, return an empty list.
    Each tuple will be sqlite3.Row objects, wherein the key:value is fieldName:value, as below:

    key: value type
    ---------------
    :primaryKey: int
    :entityFk: int
    :key: blob
    :salt: blob
    :keyTypeFk: int
    :algorithm: text
    :creationEpoch: epoch
    :expirationEpoch: epoch
    :lastUsedEpoch: epoch

    Parameters
    ----------
    entityID : str
        ID of the entity owner of the keys.
    keyType : str
        Key Type of key to retrieve (string). Only one type (not a list of types) is supported.
    notExpiredBeforeEpoch : epoch, optional
        keys will be retrieved if their `expirationEpoch` is greater than `notExpiredBeforeEpoch`.
        If `None`, `time.time()` will be utilized.
    lastUsedEpoch : epoch, optional
        the epoch of the recording. Default is None, which will then utilize the current epoch. This is an epoch float.
    database : str
        filename of authority database. If `None`, an exception will be raised.

    Returns
    -------
    list of sqlite3.Row objects
        A list of sqlite3.Row objects representing individual tuples from the database, as described above.
        It can be an empty list if no valid keys of type were found.

    Notes
    -----
    (a) Why return sqlite3.Row objects, such that tuples can be accessed through key:value dict? It looks better, and one does not have to
    bother with order or values.

    (b) The lastUsedEpoch is updated *after* the rows are retrieved. As such, the retrieved values of lastUsedEpoch are the
    values from the *previous* access, not this current one. The current lastUsedEpoch is a value close to time.time().

    """

    nowEpoch = time.time()
    if notExpiredBeforeEpoch is None:
        notExpiredBeforeEpoch = nowEpoch
    if lastUsedEpoch is None:
        lastUsedEpoch = nowEpoch

    con = sqlite3.connect(database)
    # Use the sqlite3.Row class to allow for key:value manipulation of rows.
    con.row_factory = sqlite3.Row
    with con:
        # Retrieve entity keys if any (valid ones).
        existingTuples = con.execute("""select * from entityKey where """
                             """entityFk=(select primaryKey from entity where entityID=?) and """
                             """keyTypeFk in (select primaryKey from keyType where keyType=?) and """
                             """expirationEpoch > ?""",
                             (entityID, keyType, notExpiredBeforeEpoch)).fetchall() # The expirationEpoch > time.time() here will fetch non-expired entries.
    # Update the lastUsedEpoch to reflect the last time a key was touched in the database.
    # Construct a "placeHolders" string wherein there are one ? per element in primaryKeyList.
    placeHolders = _constructPlaceHolder(existingTuples)
    query = "update entityKey set lastUsedEpoch = ? where primaryKey in %s" % placeHolders
    with con:
        # Element index [0] in each row is the primaryKey.
        con.execute(query, [lastUsedEpoch] + [row[0] for row in existingTuples])
        # Sanity check.
        if con.total_changes != len(existingTuples):
            log.error("Sanity check failed. Updated number of rows (for lastUsedEpoch) different from retrieved rows.")
            raise SystemExit("Sanity check failed. Updated number of rows (for lastUsedEpoch) different from retrieved rows.")
    # These are sqlite3.Row objects.
    return existingTuples

def createHybridABEMultiAuthorityObject(pairingGroup=constants.DEFAULT_PAIRING_GROUP):
    """
    Create a HybridABEncMA (dabenc_adapt_hybrid.py) object for use in instantiating a global parameter setup, encryption, decryption, etc.

    In particular, the global parameter setup will always utilize a global, constant random group generator, and to which a random oracle hash
    function.

    Parameters
    ----------
    pairingGroup : str, optional
        Pairing group identifier for the group object.

    Returns
    -------
    object, object, object
        HybridABEncMA object, globalParameter (from HybridABEncMA.setup method) object, PairingGroup object
    """
    # Perform the three-step Hybrid ABE object instantiation.
    # First, a PairingGroup object.
    # Second, a dabe object (decentralized ABE).
    # Third, a HybridABEncMA (Hybrid ABE nc? Multi Authority) object.
    groupObject = PairingGroup(pairingGroup)
    decentralizedABEObject = Dabe(groupObject)
    hybridDecentralizedABEObject = HybridABEncMA(decentralizedABEObject, groupObject)

    # Note here that the global parameters must be the same for all authorities, not only one, and must
    # not change unless it changes for everybody. We must now generate the global parameters and make them
    # constant, and not regenerate them!
    # Encryptions and keys do take into consideration the GlobalParameter. A different GlobalParameter will result
    # into incompatible encryptions/keys with the previous, respective generated ones with previous GlobalParameter.

    #gp = hyb_abema.setup()
    # Use the utility version such that the 'g' is a global, constant one.
    globalParameter = dabeGlobalSetup(hybridDecentralizedABEObject, groupObject)
    #print("----> GP here: ", globalParameter)
    return hybridDecentralizedABEObject, globalParameter, groupObject

def copyKeysFromOriginDatabaseToDestinationDatabase(entityID, keyType, fromDatabase, toDatabase):
        """
        Copies an entire tuple from entityKey table from an origin database to a destination database. Tuples belong to
        authorityEntityID.

        The function can be used, for example, to copy ABE authorities' ABE public keys to the Location Service database. All relevant fields
        will be copied verbatim (but the table's primaryKey), obviously considering different values for foreign keys.

        Parameters
        ----------
        entityID : str
            entityID of the owner of the ABE public keys.
        keyType : str
            keyType string that identifies the key type.
        fromDatabase : str
            filename of the database wherein the authority's ABE public keys are stored.
        toDatabase : str
            filename of the database to which the ABE public keys will be registered or copied.

        Returns
        -------
        bool
            **True** if the copy was successful for all retrieved keys; **False** if any similar record was found in the toDatabase and thus the copy failed there.

        """
        retrievedKeys = getEntityKeysOfTypeWholeTuple(entityID, keyType, database=fromDatabase)
        results = []
        # Now register each retrieved tuple to the toDatabase. Copy relevant fields verbatim.
        for row in retrievedKeys:
            results.append(registerKeyToDatabase(entityID, row['key'], row['salt'], keyType, row['algorithm'], row['creationEpoch'], row['expirationEpoch'], database=toDatabase))
        if all(results):
            log.info("Rows copied from database %s to database %s for entityID %s.", fromDatabase, toDatabase, entityID)
            return True
        else:
            log.warning("Rows copy failed. One or more rows probably already exist in the destination database/table.")
            return False

def computeKexAndNx(lengthBits=constants.RANDOM_SECRET_LENGTH_BITS, pairingGroup=constants.DEFAULT_PAIRING_GROUP):
    """
    Computes the values KEx and Nx for the LOCATHE protocol, where x is either i or r.

    Picks a random value kx and calculates (in ellyptic curve mode) kex = kx * G, where G is the group generator. It also picks a random
    value nx

    Parameters
    ----------
    lengthBits : int
        length of the random values, in bits.
    pairingGroup : str
        Pairing Group identification such that the global parameter can be computed or selected for that group.

    Returns
    -------
    pairingElement object, long int, byte str
        the kex value, which is a pairing.Element, i.e., a point in an ellyptic curve.
        the random kx value utilized to compute kex.
        the nx, a random long int as byte str.
    """
    # Get a random value kx
    kx = Crypto.Random.random.getrandbits(lengthBits)
    # Do prime group modulus arithmetic, as if it were regular Diffie-Hellman, not ellyptic curve. Charm will convert appropriately.
    hybridDecentralizedABEObject, globalParameter, groupObject = createHybridABEMultiAuthorityObject(pairingGroup=pairingGroup)
    kex = globalParameter['g'] ** kx
    #print(hashPairSha256(ker).decode(), "  ", len(hashPairSha256(ker)))
#        kerHash = Crypto.Hash.SHA256.new()
#        kerHash.update(ker)
#        print(kerHash.hexdigest())
    # Now get a random value nr.
    nx = Crypto.Random.get_random_bytes(lengthBits//8)
    return kex, kx, nx

def computeEcdheSecrets(kx, kex, ni, nr, spii, spir, outputLengthBits, hashFunction=Crypto.Hash.SHA256):
    """
    Compute the ECDHE secrets, such as shared secret session keys according to the ellyptic-curve Diffie-Hellman key exchange algorithm.

    Common:
    SharedSecret = ki * kr * G = ki * KEr = kr * KEi
    KeySeed = prf(Ni | Nr, SharedSecret)
    {SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr | … } = prf+(KeySeed, Ni | Nr | SPIi | SPIr)

    Both the prf and prf+ functions will utilize an HMAC with underlying hash function indicated by hashFunction.

    Parameters
    ----------
    kx : int
        a random value, corresponding to ki for the initiator, or kr for the responder.
    kex : pairing.Element object
        the computation of KEr = kr * G or KEi = ki * G using ellyptic curve arithmetic.
    ni : byte str
        a random value
    nr : byte str
        a random value
    spii : byte str
        the SPIi value from LOCATHE protocol.
    spir : byte str
        the SPIr value from LOCATHE protocol.
    outputLengthBits : int
        the desired length of the output of the prf+, in bits, from which keying material can be later extracted.
    hashFunction : object, optional
        the underlying hash function for the HMAC, from the Crypto.Hash library.

    Returns
    -------
    pairing.Element object, byte str
        sharedSecret value (point in ellyptic curve), to be utilized later in LOCATHE protocol.
        the concatenated keying material from which SK_ai, SK_ar, etc., will be extracted.

    Notes
    -----
    It is important to pass to this function alternate values for kx and kex, i.e., either ki and KEr, or kr and KEi, otherwise the final computation will not be
    the same for both parties.
    """
    if debug: print("kx: ", kx)
    if debug: print("kex: ", kex)
    if debug: print("ni: ", ni)
    if debug: print("nr: ", nr)
    if debug: print("spii: ", spii)
    if debug: print("spir: ", spir)
    sharedSecret = kex ** kx
    # Use the hash function after computing sharedSecret such that the pairing.Element, a point in an ellyptic curve, can be converted to a single value as bytes.
    # Bytes is the only type accepted by the hash functions.
    # Order of input is important here for all prf functions.
    #keySeed = Crypto.Hash.HMAC.new(ni + nr, hashPairSha256(sharedSecret), digestmod=hashFunction).digest()
    keySeed = prf(ni + nr, hashPair(sharedSecret), hashFunction=hashFunction)
    return sharedSecret, prfPlus(keySeed, ni + nr + spii + spir, outputLengthBits=outputLengthBits)

def prf(key, text, hashFunction=Crypto.Hash.SHA256):
    """
    Specifies a prf for use of the LOCATHE protocol.

    Parameters
    ----------
    key : byte str
        secret key for the prf.
    text : byte str
        Text input for the prf.
    hashFunction : object, optional
        the underlying hash function for the HMAC, from the Crypto.Hash library.

    Returns
    -------
    byte str
        Result of the prf.
    """
    # Compose the prf as an HMAC with underlying hashFunction. new() always used, such that each call is a new HMAC operation from a clean state.
    return Crypto.Hash.HMAC.new(key, msg=text, digestmod=hashFunction).digest()

def prfPlus(key, seed, outputLengthBits, hashFunction=Crypto.Hash.SHA256):
    """
    prf+ is defined as:

    prf+ (K,S) = T1 | T2 | T3 | T4 | ...

    where:
    T1 = prf (K, S | 0x01)
    T2 = prf (K, T1 | S | 0x02)
    T3 = prf (K, T2 | S | 0x03)
    T4 = prf (K, T3 | S | 0x04)
    ...

    The prf, here, is an HMAC with a chosen underlying hash function.

    Parameters
    ----------
    key : byte str
        secret key for the HMAC.
    seed : byte str
        the seeding material to be expanded by the prf+.
    outputLengthBits : int
        the desired length of the output of the prf+, in bits, from which keying material can be later extracted.
    hashFunction : object, optional
        the underlying hash function for the HMAC, from the Crypto.Hash library.

    Returns
    -------
    byte str
        byte value of at least outputLengthBits length in bits.
    """
    # Compute number of iterations, which is the length of the output in bits divided by the digest size (in bits) of the chosen prf.
    #iterations = math.ceil(outputLengthBits / (hashFunction.digest_size * 8))
    # Compose the prf as an HMAC with underlying hashFunction. new() always used, such that each call is a new HMAC operation from a clean state.
    #prf = lambda k, s: Crypto.Hash.HMAC.new(k, msg=s, digestmod=hashFunction).digest()
    prf_ = lambda k, s: prf(k, s)
    i = 1 # The counter concatenated at the end of the prf.
    # We use struct.pack here, with ">I", such that the counter concatenated at the end will always be the byte representation as big endiant unsigned int.
    keyMaterial = tPrevious = prf_(key, seed + struct.pack(">I", i))

    while len(keyMaterial*8) < outputLengthBits: # The len() here returns a size in bytes, therefore we convert to bits.
        i = i + 1
        t = prf_(key, tPrevious + seed + struct.pack(">I", i))
        keyMaterial = keyMaterial + t
        tPrevious = t

    # Done. Return the desired length of keyMaterial.
    return keyMaterial[:math.ceil(outputLengthBits/8)]

def serializeAndSendPayload(payload, socketFunctionBytes, pairingCurve):
    """
    Aids in preparing a payload to send through a socket, i.e., serializing the dictionary that composes the payload
    and sending through the connection socket. This is specifically for LOCATHE.

    The JSON serializer will utilize jsonhelper.KeyEncoder to serialize pairing.Element objects, if present.

    The function includes a simplified length field to facilitate receiving the whole payload by the other peer with multiple socket recv calls.

    Parameters
    ----------
    payload : dict
        Dictionary containing the payload to serialize and send.
    socketFunctionBytes : function reference
        function that sends a payload in bytes through a socket. For instance, Netservice.sendMessageThruConnectionSocketBytes().
    pairingCurve : object
        the pairing curve object that identifies the pairing curve used by jsonhelper.KeyEncoder to encode pairing.Element objects.
        Typically, the caller sends something like groupObject.param.

    Notes
    -----
    See http://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data

    """
    payloadSerialized = json.dumps(payload, cls=jsonhelper.KeyEncoder, pairingCurve=pairingCurve).encode()
    # The length of the serialized payload, which is the real length to go into the network. The total length includes the length of the length field itself, 4 octets.
    messageLength = len(payloadSerialized) + constants.MESSAGE_LENGTH_FIELD_LENGTH_BYTES
    if debug: print("Sending payload of length {}:\n".format(messageLength), payload)
    # Prefix each message with a 4-byte length (network byte order)
    payloadWithLengthField = struct.pack('>I', messageLength) + payloadSerialized
    if debug: print("payloadWithLengthField ", payloadWithLengthField)

    socketFunctionBytes(payloadWithLengthField)

def receiveAndDeserializePayload(socketFunctionBytes):
    """
    Receives a payload from the socket and deserializes it before returning it, specifically for LOCATHE.

    The function includes a simplified length field to facilitate receiving the whole payload as sent by the other peer with multiple socket recv calls.

    Parameters
    ----------
    socketFunctionBytes : function reference
        function that receives a payload in bytes through a socket. For instance, Netservice.receiveMessageThruMainSocketBytes().

    Returns
    -------
    dict
        Deserialized payload received from the socket.

    Notes
    -----
    See http://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data
    """
    # First, capture the message length and deduct the length of the length field itself (4 bytes).
    rawMessageLength = socketFunctionBytes(bufferSize=constants.MESSAGE_LENGTH_FIELD_LENGTH_BYTES)
    messageLength = struct.unpack(">I", rawMessageLength)[0] # unpack returns a tuple with one value, or (n,).
    payloadLength = messageLength - constants.MESSAGE_LENGTH_FIELD_LENGTH_BYTES

    # Now retrieve the whole payload as indicated by the length field (minus its size).
    payload = b''
    while len(payload) < payloadLength:
        segment = socketFunctionBytes(bufferSize = payloadLength - len(payload))
        if not segment: # Connection was likely closed.
            return None
        payload += segment
    payloadDeserialized = json.loads(payload.decode(), cls=jsonhelper.KeyDecoder)
    if debug: print("Receiving payload:\n", payloadDeserialized)
    return payloadDeserialized

def sendMessage(spii, spir, exchangeType, messageType, sender, counter, payload, socketFunctionBytes, pairingCurve):
    """
    Sends a LOCATHE message (with header) through a socket, i.e., composing the header, serializing the dictionary that composes the payload
    and sending through the connection socket.

    The JSON serializer will utilize jsonhelper.KeyEncoder to serialize pairing.Element objects, if present.

    The function computes and adds the length as a first field to facilitate receiving the whole payload by the other peer with multiple socket recv calls.

    Parameters
    ----------
    spii : byte str
        Security Parameter Index of the Initiator
    spir : byte str
        Security Parameter Index of the Responder
    exchangeType : int
        The type of exchange to which this message belongs.
    messageType : bool
        True if it is a response message, False if it is a request message.
    sender : bool
        True if this message was generated by the Initiator; False if this message was generated by the Responder.
    counter : int
        Message counter.
    payload : dict
        Dictionary containing the payload to serialize and send.
    socketFunctionBytes : function reference
        function that sends a payload in bytes through a socket. For instance, Netservice.sendMessageThruConnectionSocketBytes().
    pairingCurve : object
        the pairing curve object that identifies the pairing curve used by jsonhelper.KeyEncoder to encode pairing.Element objects.
        Typically, the caller sends something like groupObject.param.

    Returns
    -------
    byte str
        The raw message that will be sent through the socket. Returning the exact raw message facilitates the calculation of <SignedOctets> by the
        protocol.

    Notes
    -----
    See http://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data

    """
    if debug: print("Payload to serialize: ", payload)
    payloadSerialized = json.dumps(payload, cls=jsonhelper.KeyEncoder, pairingCurve=pairingCurve).encode()
    # Build the header. The header builder will calculate the appropriate final length.
    payloadLength = len(payloadSerialized)
    header = constructLocatheHeader(spii, spir, exchangeType, messageType, sender, counter, payloadLength)
    if debug: print("Header: ", header)
    # The length of the message comprises the serialized payload and the length of the header.
    totalLength = len(header) + payloadLength
    message = header + payloadSerialized
    if debug: print("Sending message of calculated length {} and reported length {}:\n".format(totalLength, len(message)), message)

    socketFunctionBytes(message)
    return message

def sendMessageRawAttackTest(socketFunctionBytes, rawMessage):
    """
    Sends a LOCATHE raw message (any raw message, for that purpose) through a socket.

    The rawMessage must be in proper LOCATHE format in byte mode such that it can be received properly by the other peer (but
    not necessarily accepted as valid). The purpose of the function is to test certain attack vectors, for instance, sending
    the same message to the same peer after a time (replay attack) or to another peer to test their reaction.

    The function performs no header computation or serialization: the header must be part of the raw message and the message
    must be properly serialized.

    Parameters
    ----------
    socketFunctionBytes : function reference
        function that sends a payload in bytes through a socket. For instance, Netservice.sendMessageThruConnectionSocketBytes().
    payload : byte str
        Byte str containing the raw message to send.

    Notes
    -----
    See http://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data

    """
    if debug: print("Sending raw attack mode message of reported length {}:\n".format(len(rawMessage)), rawMessage)

    socketFunctionBytes(rawMessage)

def receiveMessage(socketFunctionBytes):
    """
    Receives a LOCATHE message from the socket and returns a dictionary containing all payload fields(key/values) and a sub-dict for the header
    ([header][field]) within the same dict.

    Parameters
    ----------
    socketFunctionBytes : function reference
        function that receives a payload in bytes through a socket. For instance, Netservice.receiveMessageThruMainSocketBytes().

    Returns
    -------
    dict
        Deserialized payload received from the socket, and a sub-dict containing the header information under the key [header].
        Or empty b'' to signal closed connection.

    Notes
    -----
    See http://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data
    """
    # First, capture the entire header and unpack it to a dictionary.
    headerRaw = socketFunctionBytes(bufferSize=struct.calcsize(constants.HEADER_STRUCT_FORMAT))
    # If nothing was received, then the other peer closed the connection. Return empty to signal that.
    if not headerRaw:
        return b''
    headerDict = headerStructToDict(headerRaw)
    if debug: print("locationserviceutility receiveMessage: header received: ", headerDict)
    # Extract the message length and deduct the length of the header, such that we can obtain the length of the payload only.
    payloadLength = headerDict[constants.HEADER_FIELD_NAME][constants.HEADER_FIELD_NAME_MESSAGE_LENGTH] - struct.calcsize(constants.HEADER_STRUCT_FORMAT)
    if debug: print("locationserviceutility receiveMessage: payloadLength: ", payloadLength)
    # Now retrieve the whole payload as indicated by the length field (minus its size).
    payload = b''
    while len(payload) < payloadLength:
        segment = socketFunctionBytes(bufferSize = payloadLength - len(payload))
        if debug: print("locationserviceutility receiveMessage: segment: ", segment)
        if not segment: # Connection was likely closed.
            return None
        payload += segment
    payloadDeserialized = json.loads(payload.decode(), cls=jsonhelper.KeyDecoder)
    if debug: print("locationserviceutility receiveMessage: payloadDeserialized: ", payloadDeserialized, " type: ", type(payloadDeserialized))
    # Merge the header and payload dicts.
    # Note: one cannot assign a dict to the result of another dict update method. The update method for dict returns None. So one gets a None value.
    payloadDeserialized.update(headerDict)
    # To allow for calculating <SignedOctets>, include the raw message in the dictionary.
    payloadDeserialized.update({constants.PAYLOAD_FIELD_NAME_RAW_MESSAGE: headerRaw + payload})
    if debug: print("Receiving message:\n", payloadDeserialized)
    return payloadDeserialized

def sendEncryptedMessage(spii, spir, exchangeType, messageType, sender, counter, payload, socketFunctionBytes, pairingCurve, key):
    """
    Sends a LOCATHE encrypted message (with header) through a socket, i.e., composing the header, serializing the dictionary that composes the payload
    and sending through the connection socket.

    Only the payload is encrypted. The encryption mode is AEAD (Authenticated Encryption with Additional Data), such that the payload is authenticated
    and the header is also authenticated as associated, plaintext data.

    The JSON serializer will utilize jsonhelper.KeyEncoder to serialize pairing.Element objects, if present.

    The function computes and adds the length as a first field to facilitate receiving the whole payload by the other peer with multiple socket recv calls.

    Parameters
    ----------
    spii : byte str
        Security Parameter Index of the Initiator
    spir : byte str
        Security Parameter Index of the Responder
    exchangeType : int
        The type of exchange to which this message belongs.
    messageType : bool
        True if it is a response message, False if it is a request message.
    sender : bool
        True if this message was generated by the Initiator; False if this message was generated by the Responder.
    counter : int
        Message counter.
    payload : dict
        Dictionary containing the payload to serialize and send.
    socketFunctionBytes : function reference
        function that sends a payload in bytes through a socket. For instance, Netservice.sendMessageThruConnectionSocketBytes().
    pairingCurve : object
        the pairing curve object that identifies the pairing curve used by jsonhelper.KeyEncoder to encode pairing.Element objects.
        Typically, the caller sends something like groupObject.param.
    key : byte str
        The symmetric secret key utilized to encrypt the payload (*not* the header).

    Returns
    -------
    byte str
        The raw message that will be sent through the socket. Returning the exact raw message facilitates the calculation of <SignedOctets> by the
        protocol.

    Notes
    -----
    See http://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data

    """
    if debug: print("Payload to serialize: ", payload)
    payloadSerialized = json.dumps(payload, cls=jsonhelper.KeyEncoder, pairingCurve=pairingCurve).encode()
    # Build the header. The header builder will calculate the appropriate final length.
    payloadLength = len(payloadSerialized)

    # Fixed encryption overhead due to Charm: 194?
    # To estimate encryption length:
    # Calculate PKCS7 padding: pkcs7padded = blockSize - (message % blockSize)
    # Compute base64 overhead: base64encoded = 4 * ceil(pkcs7padded / 3)
    # Add fixed Charm overhead: base64encoded + 194
    pkcs7paddedPayloadLength = payloadLength + (constants.AES_BLOCK_SIZE_BYTES - (payloadLength % constants.AES_BLOCK_SIZE_BYTES))
    base64overheadAddedPayloadLength = 4 * math.ceil(pkcs7paddedPayloadLength / 3)
    estimatedEncryptedPayloadLength = base64overheadAddedPayloadLength + constants.CHARM_AUTHENTICATEDCRYPTOABSTRACTION_FIXED_OVERHEAD_BYTES
    header = constructLocatheHeader(spii, spir, exchangeType, messageType, sender, counter, estimatedEncryptedPayloadLength)
    if debug: print("Header: ", header)
    cipher = charm.toolbox.symcrypto.AuthenticatedCryptoAbstraction(key)
    # Use generic JSON serializing here without custom helpers. The sensitive payload is already encrypted and thus has no sensitive data such as pairing.Element objects.
    payloadEncrypted = json.dumps(cipher.encrypt(payloadSerialized, header)).encode()
    if debug: print("payloadEncrypted:\n", payloadEncrypted)

    # The length of the message comprises the serialized payload and the length of the header.
    totalLength = len(header) + payloadLength
    estimatedTotalLength = len(header) + estimatedEncryptedPayloadLength
    if debug: print("totalLength: ", totalLength)
    if debug: print("estimatedTotalLength: ", estimatedTotalLength)
    message = header + payloadEncrypted
    assert(estimatedTotalLength == len(message))
    if debug: print("Sending message of calculated length {} and reported length {}:\n".format(totalLength, len(message)), message)

    socketFunctionBytes(message)
    return message

def receiveEncryptedMessage(socketFunctionBytes, key):
    """
    Receives a LOCATHE encrypted message from the socket and returns a dictionary containing all payload fields(key/values) and a sub-dict for the header
    ([header][field]) within the same dict. I.e., this function decrypts the message using the provided symmetric secret key.

    The encryption is expected to be AEAD (Authenticated Encryption with Additional Data), such that both the payload and header are authenticated.

    Parameters
    ----------
    socketFunctionBytes : function reference
        function that receives a payload in bytes through a socket. For instance, Netservice.receiveMessageThruMainSocketBytes().
    key : byte str
        The symmetric secret key utilized to encrypt the payload (*not* the header).

    Returns
    -------
    dict
        Deserialized payload received from the socket, and a sub-dict containing the header information under the key [header].

    Raises
    ------
    ValueError
        If the authentication fails.

    Notes
    -----
    See http://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data
    """
    encryptedPayload = receiveMessage(socketFunctionBytes)
    # If nothing was received, then the connection was closed by the other peer. Signal that by returning empty b''.
    if not encryptedPayload:
        return b''
    cipher = charm.toolbox.symcrypto.AuthenticatedCryptoAbstraction(key)
    # The headerRaw is the associated data for authentication.
    headerRaw = extractHeaderFromRawMessage(encryptedPayload[constants.PAYLOAD_FIELD_NAME_RAW_MESSAGE])
    # The headerDict has to be included back into the dict after decryption, since Charm's decryption erases all unknown key:value pairs.
    headerDict = encryptedPayload[constants.HEADER_FIELD_NAME]

    try:
        decryptedPayload = cipher.decrypt(encryptedPayload, headerRaw)
    except ValueError:
        log.exception("MAC verification failed.")
        raise ValueError("locationserviceutility: receiveEncryptedMessage: MAC verification failed.")

    # The decrypted message has only the original dictionary that would compose the plaintext message, without any raw message key:value.
    # Let's put the raw message into the dict before returning it, together with the headerDict.
    decryptedPayloadDict = json.loads(decryptedPayload.decode(), cls=jsonhelper.KeyDecoder)
    decryptedPayloadDict.update({constants.PAYLOAD_FIELD_NAME_RAW_MESSAGE: encryptedPayload[constants.PAYLOAD_FIELD_NAME_RAW_MESSAGE]})
    decryptedPayloadDict.update({constants.HEADER_FIELD_NAME: headerDict})
    if debug: print("locationserviceutility receiveEncryptedMessage dictd:\n", decryptedPayloadDict)
    return decryptedPayloadDict

def extractHeaderFromRawMessage(rawMessage):
    """
    Extract the LOCATHE header, in bytes, from a raw (byte str) message, and returns the header.

    Parameters
    ----------
    rawMessage : byte str
        The raw message in bytes composed of header and payload.

    Returns
    -------
    byte str
        The byte str consisting of the header only.
    """
    # Use HEADER_STRUCT_FORMAT to compute the size of the header and return it.
    return rawMessage[:struct.calcsize(constants.HEADER_STRUCT_FORMAT)]


def extractPayloadFromRawMessage(rawMessage):
    """
    Extract the LOCATHE payload, in bytes, from a raw (byte str) message, and returns this payload.

    Parameters
    ----------
    rawMessage : byte str
        The raw message in bytes composed of header and payload.

    Returns
    -------
    byte str
        The byte str consisting of the payload only.
    """
    # Use HEADER_STRUCT_FORMAT to compute the size of the header and return the rest of the rawMessage minus the header
    return rawMessage[struct.calcsize(constants.HEADER_STRUCT_FORMAT):]

def headerStructToDict(header):
    """
    Converts a header from a LOCATHE message, formatted as a byte-struct, into a dict with key/values in [header][field] : value format.

    Parameters
    ----------
    header : struct
        byte struct representing the header from a LOCATHE message.

    Returns
    -------
    dict
        dict in the format [header][header-field] : value.
    """
#    flags = 0b00000000
#    mask = 0b00000000
#    if sender:
#        mask = mask | constants.HEADER_SENDER_TYPE_BITMASK
#    if messageType:
#        mask = mask | constants.HEADER_MESSAGE_TYPE_BITMASK
#    flags = flags | mask
#    totalLength = payloadLength + struct.calcsize(constants.HEADER_STRUCT_FORMAT)
#    # Reset all flags that are unused. Not really necessary here the way it is being designed, but let's do it.
#    flags = flags & constants.HEADER_FIELD_FLAGS_RESET_UNUSED_MASK
#    header = struct.pack(constants.HEADER_STRUCT_FORMAT, totalLength, spii, spir, flags.to_bytes(1, byteorder= 'big'), exchangeType, bytes(1), bytes(1), counter)
    length, spii, spir, flags, exchangeType, dummy1, dummy2, messageCounter = struct.unpack(constants.HEADER_STRUCT_FORMAT, header)
    # Process the flags field to extract the specific flag values.
    # Sender type, which is either True or False.
    sender = constants.HEADER_SENDER_TYPE_INITIATOR if int.from_bytes(flags, byteorder='big') & constants.HEADER_SENDER_TYPE_BITMASK else constants.HEADER_SENDER_TYPE_RESPONDER
    # MessageType, which is also either True or False.
    messageType = constants.HEADER_MESSAGE_TYPE_RESPONSE if int.from_bytes(flags, byteorder='big') & constants.HEADER_MESSAGE_TYPE_BITMASK else constants.HEADER_MESSAGE_TYPE_REQUEST
    # Build the dictionary.
    headerDict = {constants.HEADER_FIELD_NAME: {constants.HEADER_FIELD_NAME_MESSAGE_LENGTH: length,
                                                constants.HEADER_FIELD_NAME_SPI_I: spii,
                                                constants.HEADER_FIELD_NAME_SPI_R: spir,
                                                constants.HEADER_FIELD_NAME_EXCHANGE_TYPE: exchangeType,
                                                constants.HEADER_FIELD_NAME_SENDER_TYPE: sender,
                                                constants.HEADER_FIELD_NAME_MESSAGE_TYPE: messageType,
                                                constants.HEADER_FIELD_NAME_MESSAGE_COUNTER: messageCounter}}

    return headerDict

def constructLocatheHeader(spii, spir, exchangeType, messageType, sender, counter, payloadLength):
    """
    Prepares a struct representing the header of a LOCATHE protocol message for sending over the network.

    Tentatively, the LOCATHE header, adapted from IKEv2, is:

                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Length (4 octets)                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Initiator's SPIi                       |
    |                           (8 octets)                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Responder's SPIr                       |
    |                           (8 octets)                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Flags (1 octet)| Exchange Type | MjVer | MnVer | Next Payload  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                   Message Counter (4 octets)                  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    MjVer, MnVer, Next Payload are currently unused.

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
         responses. Therefore, R=1 for response, R=0 for request.

    *  I (Initiator) - This bit MUST be set in messages sent by the
         original initiator of the message and MUST be cleared in
         messages sent by the original responder.  It is used by the
         recipient to determine which 8 octets of the SPI were generated
         by the recipient. Therefore, I=1 for initiator, I=0 for responder.

    *  X - unused.


    Parameters
    ----------
    spii : byte str
        Security Parameter Index of the Initiator
    spir : byte str
        Security Parameter Index of the Responder
    exchangeType : int
        The type of exchange to which this message belongs.
    messageType : bool
        True if it is a response message, False if it is a request message.
    sender : bool
        True if this message was generated by the Initiator; False if this message was generated by the Responder.
    counter : int
        Message counter.
    payloadLength : int
        The length of they payload only, in bytes. The function will add the length of the header itself to this value to compose the final length.

    Returns
    -------
    byte struct
        Byte struct representing the message header EXCEPT for the length field.
    """
    # Reset flags field, and the mask, to start.
    flags = 0b00000000
    mask = 0b00000000
    if sender: # if sender is Initiator, set the bit. Otherwise, keep it 0.
        mask = mask | constants.HEADER_SENDER_TYPE_BITMASK
    if messageType: # if messageType is Response, set the bit. Otherwise, keep it 0.
        mask = mask | constants.HEADER_MESSAGE_TYPE_BITMASK
    flags = flags | mask
    totalLength = payloadLength + struct.calcsize(constants.HEADER_STRUCT_FORMAT)
    # Reset all flags that are unused. Not really necessary here the way it is being designed, but let's do it.
    flags = flags & constants.HEADER_FIELD_FLAGS_RESET_UNUSED_MASK
    header = struct.pack(constants.HEADER_STRUCT_FORMAT, totalLength, spii, spir, flags.to_bytes(1, byteorder= 'big'), exchangeType, bytes(1), bytes(1), counter)
    return header

def validateMessageHeader(agentObject, header, exchangeType, messageType, enforceSpiCheck=True):
    """
    Validates the header of a received message, i.e., checks whether SPI values match, the expected message counter is correct, whether the exchangeType is the one expected,
    the messageType is the one expected, the message sender is the initiator.

    This is not an inner, sub-level dictionary, but an outer, first level dictionary, i.e., [header_field] : value, [header_field]: value, etc.

    Parameters
    ----------
    agentObject : object
        The object representing the Location Service agent or User agent.
    header : dict
        The header to be verified in dict format.
        This is not an inner, sub-level dictionary, but an outer, first level dictionary, i.e., [header_field] : value, [header_field]: value, etc.
    exchangeType : int
        The type of exchange to which this message belongs.
    messageType : bool
        True if it is a response message, False if it is a request message.
    enforceSpiCheck : bool, optional
        If True, the header SPI values will be checked against the expected ones. If False, check will not be made.
        The purpose is to allow an agent to actually receive yet unknown SPI values from the other peer and set them locally, and then enforce checking for
        subsequent messages.

    Returns
    -------
    bool
        True if header is valid, i.e., all values are those expected.
        False otherwise.
    """
    # If the caller of the function is the Location Service, that means the message was *received* by the Location Service, and thus is expected to have
    # been sent by the user agent peer.  Therefore, the sender type is INITIATOR.
    # Otherwise, if the caller of the function is the user agent, then the message was *received* by the user agent, and thus the message is expected
    # to have been sent by the Location Service. Therefore, the sender type now is RESPONDER.
    if agentObject.agentType == constants.LOCATHE_LOCATION_SERVICE_AGENT_TYPE:
        # the caller if Location Service. Set the message sender to INITIATOR (the user agent).
        receivedMessageHeaderSenderType = constants.HEADER_SENDER_TYPE_INITIATOR
    else:
        # Otherwise, the caller is the user agent, and thus the message sender should be the Location Service.
        receivedMessageHeaderSenderType = constants.HEADER_SENDER_TYPE_RESPONDER

#    if debug: print("---- validateMessageHeader ----")
#    if debug: print("(enforceSpiCheck and header[constants.HEADER_FIELD_NAME_SPI_I] != agentObject.spii): ", (enforceSpiCheck and header[constants.HEADER_FIELD_NAME_SPI_I] != agentObject.spii))
#    if debug: print("(enforceSpiCheck and header[constants.HEADER_FIELD_NAME_SPI_R] != agentObject.spir): ", (enforceSpiCheck and header[constants.HEADER_FIELD_NAME_SPI_R] != agentObject.spir))
#    if debug: print("header[constants.HEADER_FIELD_NAME_EXCHANGE_TYPE] != exchangeType: ", header[constants.HEADER_FIELD_NAME_EXCHANGE_TYPE] != exchangeType)
#    if debug: print("header[constants.HEADER_FIELD_NAME_SENDER_TYPE] != receivedMessageHeaderSenderType: ", header[constants.HEADER_FIELD_NAME_SENDER_TYPE] != receivedMessageHeaderSenderType)
#    if debug: print("header[constants.HEADER_FIELD_NAME_MESSAGE_TYPE] != messageType: ", header[constants.HEADER_FIELD_NAME_MESSAGE_TYPE] != messageType)
#    if debug: print("header[constants.HEADER_FIELD_NAME_MESSAGE_COUNTER] != agentObject.expectedReceivedMessageCounter: ", header[constants.HEADER_FIELD_NAME_MESSAGE_COUNTER] != agentObject.expectedReceivedMessageCounter)
#    if debug: print("-------------------------------")

    if (enforceSpiCheck and header[constants.HEADER_FIELD_NAME_SPI_I] != agentObject.spii) or \
       (enforceSpiCheck and header[constants.HEADER_FIELD_NAME_SPI_R] != agentObject.spir) or \
        header[constants.HEADER_FIELD_NAME_EXCHANGE_TYPE] != exchangeType or \
        header[constants.HEADER_FIELD_NAME_SENDER_TYPE] != receivedMessageHeaderSenderType or \
        header[constants.HEADER_FIELD_NAME_MESSAGE_TYPE] != messageType or \
        header[constants.HEADER_FIELD_NAME_MESSAGE_COUNTER] != agentObject.expectedReceivedMessageCounter:
        return False
    else:
        return True

def generateSpiRandomValue(length=constants.SPI_LENGTH_BYTES):
    """
    Generates a random value of constants.SPI_LENGTH_BYTES length for use as an SPI value. Zero is not accepted, therefore the function assures it does not
    happen.

    Parameters
    ----------
    length : int, optional
        Length, in bytes, of the random value to be generated.

    Returns
    -------
    byte str
        Random value of length 'length' as a byte string. Zero is not a possibility.
    """
    # Construct a sequence of zero bytes the specified length.
    zeros = b'\x00' * length
    randomSpi = zeros
    while randomSpi == zeros:
        randomSpi = Crypto.Random.get_random_bytes(length)
    return randomSpi

def computeSignedOctets(rawMessage, nValue, idPayload, prfKey, hashFunction=Crypto.Hash.SHA256):
    """
    Compute the <SignedOctets> value for LOCATHE authentication.

    From RFC 7296

    The initiator's signed octets can be described as:

    InitiatorSignedOctets = RealMessage1 | NonceRData | MACedIDForI
       GenIKEHDR = [ four octets 0 if using port 4500 ] | RealIKEHDR
       RealIKEHDR =  SPIi | SPIr |  . . . | Length
       RealMessage1 = RealIKEHDR | RestOfMessage1
       NonceRPayload = PayloadHeader | NonceRData
       InitiatorIDPayload = PayloadHeader | RestOfInitIDPayload
       RestOfInitIDPayload = IDType | RESERVED | InitIDData
       MACedIDForI = prf(SK_pi, RestOfInitIDPayload)

    The responder's signed octets can be described as:

    ResponderSignedOctets = RealMessage2 | NonceIData | MACedIDForR
       GenIKEHDR = [ four octets 0 if using port 4500 ] | RealIKEHDR
       RealIKEHDR =  SPIi | SPIr |  . . . | Length
       RealMessage2 = RealIKEHDR | RestOfMessage2
       NonceIPayload = PayloadHeader | NonceIData
       ResponderIDPayload = PayloadHeader | RestOfRespIDPayload
       RestOfRespIDPayload = IDType | RESERVED | RespIDData
       MACedIDForR = prf(SK_pr, RestOfRespIDPayload)

    Parameters
    ----------
    rawMessage : byte str
        The raw message wherein Diffie-Helmann values were exchanged and was not protected by encryption. Usually the first message exchanged.
    nValue : byte str
        The nonce value provided by the other party, which this party will authenticate as the one received.
    idPayload : byte str
        The id of this party.
    prfKey : byte str
        The secret key utilized by the prf to compute the value prf(SK_p, idPayload)
    hashFunction : object, optional
        the underlying hash function for the HMAC, from the Crypto.Hash library.

    Returns
    -------
    byte str
        The <SignedOctets> value.
    """
#    print("rawMessage ", type(rawMessage))
#    print("nvalue ", type(nValue))
#    print("prfKey ", type(prfKey))
#    print("idPayload ", type(idPayload))
    return rawMessage + nValue + prf(prfKey, idPayload, hashFunction=hashFunction)

def buildAnonymousIdPayload():
    """
    Builds an anonymous ID payload, with an anonymous userID. This is intended for usage of LOCATHE Tier 1 Privacy authentication, wherein a user
    does not uniquely identify herself, nevertheless must compute an AUTH payload with some ID (to maintain proximity with IKEv2 computing methods).
    Therefore, we utilize an anonymous userID.

    Returns
    -------
    byte str
        A JSON serialized and byte-str-encoded ID payload with an anonymous userID.
    """
    return json.dumps({constants.PAYLOAD_FIELD_NAME_ID_I: constants.ENTITY_ID_TIER1_ANONYMOUS_USER}).encode()

def computeAuthTier(literalString, signedOctets, ni, nr, nb, keValue):
    """
    Computes the AUTH_TIER1 or AUTH_TIER2 value (initiator or responder). The literalString and SignedOctets define whether the resulting
    computation will be TIER1 or TIER2 (in particular, signedOctets contains an anonymous user ID in Tier1, but a non-anonymous user ID in Tier2).

    Parameters
    ----------
    literalString : byte str
        A literal string that complements the value in the inner prf+ that results in the key for the prf.
    signedOctets : byte str
        <SignedOctets> pre-computed value (with the appropriate function and arguments).
    ni : byte str
        The Ni value from LOCATHE, the random nonce from the initiator.
    nr : byte str
        The Nr value from LOCATHE, the random nonce from the responder.
    nb : byte str
        The Nb random nonce created by the Location Service.
    keValue : pairing.Element object
        the computation of KEr = kr * G or KEi = ki * G using ellyptic curve arithmetic.
        KEr for AUTH_TIER1_i, and KEi for AUTH_TIER1_r.

    Returns
    -------
    byte str
        AUTH_TIER1 value.
    """
    # AUTH_TIER1_i = prf(prf+(Ni | Nr, “LocAuth Tier_1” | Nb), <SignedOctets_i> | KEr).
    # AUTH_TIER2_i = prf(prf+(Ni | Nr, “LocAuth Tier_2” | Nb), <SignedOctets_i> | KEr)
    # signed_octets = bytes(self.packets[0]) + self.Nr + prf(self.SK_pi, id_payload._data)
    # Before computing AUTH value, certain values must be converted to appropriate byte str, such as KEx values that are (x,y) points.
    # Update current BNONCE/Nb.
    authTier = prf(prfPlus(ni + nr, literalString + nb, constants.AUTH_PRFPLUS_KEY_LENGTH_BITS), signedOctets + hashPair(keValue))
    return authTier

def isEntityIDvalid(entityID, database=None):
    """
    Verifies whether an entityID exists in the database. Returns True if entityID exists there, False otherwise.
    Specifically, the table entity is searched.

    Parameters
    ----------
    entityID : str
        entityID to verify.
    database : str
        filename of the database file. If `None`, an exception will be raised.

    Returns
    -------
    bool
        True if entityID was found in the entity table in database.
        False if entityID was not found in the database.
    """

    con = sqlite3.connect(database)
    with con:
        # Get the entities whose name matches the searchString.
        primaryKey = con.execute("select primaryKey from entity where entityID = ?", (entityID,)).fetchone()
    if primaryKey:
        return True
    else:
        return False

def getKeyTypeFactorScore(keyType, database=None):
    """
    Return the `keyType` factorScore per the key type description (string).

    Parameters
    ----------
    keyType : str
        `keyType` description.
    database : str
        filename of database. If `None`, an exception will be raised.

    Returns
    -------
    int
        `keyType` factorScore.
        It can be None; undecided whether the None should be treated here (e.g., return zero instead) or at the calling function.
    """
    # Check whether database was passed as argument.
    if database is None:
        # Exit immediately after logging error.
        log.error("Database filename is None. It must not be undefined.")
        raise SystemExit("Database filename is None. It must not be undefined.")

    con = sqlite3.connect(database)
    with con:
        # TODO:
        # It can be None; undecided whether the None should be treated here (e.g., return zero instead) or at the calling function.
        return con.execute("select factorScore from keyType where keyType=?", (keyType,)).fetchone()[0]
