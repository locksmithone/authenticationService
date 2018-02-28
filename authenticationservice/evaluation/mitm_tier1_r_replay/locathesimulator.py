# -*- coding: utf-8 -*-
"""
Created on Sun Apr 24 16:59:44 2016

@author: locksmith
"""

#import authenticationservice
import abeauthorityagent
import locationserviceagentsimulator
import useragentsimulator
import locationservice
import useragent
import locationserviceutility
import time
import constants
import logging
import multiprocessing
import collections

debug = True # Set to True to print debugging messages while running.

class LocatheSimulator(object):
    """
    This simulates a run of the Locathe protocol, as if performed by a user agent, an authority/RP agent, and the
    Location Service.

    References
    ----------
        http://dx.doi.org/10.1109/ICCNC.2016.7440584
    """

    def __init__(self, authorityEntityID, authorityEntityType, authorityName, authorityAttributes,
                 userEntityID, userEntityType, userName, userAttributes,
                 locationServiceDatabase,
                 authorityDatabase,
                 userDatabase):
        """
        This simulates a run of the Locathe protocol, as if performed by a user agent, an authority/RP agent, and the
        Location Service.

        Parameters
        ----------
        authorityEntityID : str
            ID of the authority to create/simulate (string).
        authorityEntityType : int
            Type of the authority (see database), integer.
        authorityName : str
            Name of the authority (string).
        authorityAttributes : list of str
            List of string (unique) attributes for this authority (all attributes).
        userEntityID : str
            ID of the user to create/simulate (string).
        userEntityType : int
            Type of the user (see database), integer.
        userName : str
            Name of user (string).
        userAttributes : list of str
            List of string (unique) attributes that this user has, within the set of all authority attributes.
        locationServiceDatabase : str
            filename for location service database.
        authorityDatabase : str
            filename for authority database.
        userDatabase : str
            filename for user agent database.

        Attributes
        ----------
        log : logger object
            logger object to manipulate logging.
        authorityEntityID : str
            ID of the authority to create/simulate (string).
        authorityEntityType : int
            Type of the authority (see database), integer.
        authorityName : str
            Name of the authority (string).
        authorityAttributes : list of str
            List of string (unique) attributes for this authority (all attributes).
        userEntityID : str
            ID of the user to create/simulate (string).
        userEntityType : int
            Type of the user (see database), integer.
        userName : str
            Name of user (string).
        userAttributes : list of str
            List of string (unique) attributes that this user has, within the set of all authority attributes.
        locationServiceDatabase : str
            filename for location service database.
        authorityDatabase : str
            filename for authority database.
        userDatabase : str
            filename for user agent database.
        locationServiceObj : locationservice.LocationService object
            locationservice.LocationService object
        abeAuthorityObj : abeauthorityagent.ABEAuthority object
            abeauthorityagent.ABEAuthority object
        userAgentObj : useragent.UserAgent object
            useragent.UserAgent object

        References
        ----------
            http://dx.doi.org/10.1109/ICCNC.2016.7440584

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

        # Populate variables with databases and other miscellanea.
        # Create one object of each user agent, authority agent, Location Service.
        self.locationServiceDatabase = locationServiceDatabase
        self.authorityDatabase = authorityDatabase
        self.userDatabase = userDatabase
        self.authorityEntityID = authorityEntityID
        self.authorityEntityType = authorityEntityType
        self.authorityName = authorityName
        self.userEntityID = userEntityID
        self.userName = userName
        self.userEntityType = userEntityType
        self.locationServiceObj = locationservice.LocationService(database = self.locationServiceDatabase)
        self.abeAuthorityObj = abeauthorityagent.ABEAuthority(self.authorityEntityID, database = self.authorityDatabase)
        self.userAgentObj = useragent.UserAgent(self.userEntityID, database = self.userDatabase)

        # Objects for the agent simulators (which will run the protocols simulating real devices/agents).
        self.locationServiceAgentSimulator = locationserviceagentsimulator.LocationServiceAgentSimulator(self.locationServiceObj, agentType=constants.LOCATHE_LOCATION_SERVICE_AGENT_TYPE)
        self.userAgentSimulator = useragentsimulator.UserAgentSimulator(self.userAgentObj, agentType=constants.LOCATHE_USER_AGENT_TYPE)

        self.authorityAttributes = authorityAttributes

        self.userAttributes = userAttributes


    def simulateRegistration(self):
        """
        This function simulates the registration phase, wherein parties exchange security parameters for future runs of the
        protocol.

        Registration procedure (draft):

        User - Location Service:
        _ (user) Entity ID.
        _ User attributes.
        _ User TOTP secret.
        _ User secret key or password.
        _ Location Service PKI public key.

        User - Authority:
        _ User attributes.
        _ User ABE secret keys.
        _ User secret key.
        """

        #expirationEpoch = time.time() + constants.DEFAULT_AUTHORITY_KEY_EXPIRATION_SECONDS
        # Authority Agent: create authority, attributes, and authority's ABE keys and PKI keys. (TOTP secret?)
        # Create authority (if it yet does not exist), all three databases.
        self.createAuthority()

        # Create some attributes for the authority, if they do not exist already. But first create the attributes themselves, if they
        # do not yet exist.
        # All databases.
        self.createAttributesAuthority()

        # Now, create the user.
        # All databases.
        self.createUser()

        # Register attributes for user.
        # All databases (albeit initially the user does not need to know which attributes she has, since she will have the keys nevertheless).
        self.registerUserAttributes()

        # Create TOTP secret for user.
        # Location Service and user databases.
        self.createTotpSecrets()

        # Create Location Service PKI keys, if they do not yet exist.
        # This is actually automatically done when the Location Service object is instantiated.
        # The constructor looks for the PKI files and instantiates the public and private key object attributes.
        # Or, if the files do not exist, the constructor will create new public/private keys and put the values
        # into the object attributes.
        # So, to access the public and private PKI keys, just use the object's attributes.
        # Nothing to do here!
        self.createLocationServicePKIKeys()

        # Create and register ABE keys for authority, Location Service, user.
        # Need to create the ABE public and secret keys for authority for all authority's attributes.
        # Create ABE secret keys for user based on user's attributes.
        # Then register secret and public ABE keys in authority database, ABE public keys in Location Service database,
        # and user secret ABE keys in user database.
        # Must implement the appropriate functions to create ABE secret keys based on user's attributes.
        # Decision: will the authority's ABE keys be created/retrieved upon instantiation of object (such as Location Service
        # object), or shall we call the appropriate function?
        # And, shall we create the authority's and user's ABE keys based on the attributes of each as registered in the database?
        # In this case, we do not necessarily need to pass the attributes to the creation function: the function would simply
        # ready the attributes off the database. Or, we create another interface function to read these attributes and then
        # this function will call the create function.

        # Decision: we populate each authority's own set of attributes in the entityAttribute table in the database. Then, to create
        # ABE keys, a function needs only read the attributes off the database. (Of course, to encrypt a message, we need an access
        # policy.)
        # Decision: 2016.09.06: We create/get the authority's ABE keys upon instantiation of the authority's object, including Location Service.
        #   Might change this in the future.
        self.createAuthorityABEKeys(self.abeAuthorityObj.entityID)
        self.createLocationServiceABEKeys(self.locationServiceObj.entityID)
        self.createABEUserKeys(self.userAgentObj, self.abeAuthorityObj, self.locationServiceObj)
        # Register authority's ABE public keys to the Location Service database.
        self.copyAbePublicKeysFromOriginDatabaseToDestinationDatabase(self.abeAuthorityObj.entityID, self.abeAuthorityObj.database, self.locationServiceObj.database)
        # Create shared keys of each keyType for user (and Location Service).
        self.createAuthenticationFactors(expireExistingKeys=False)

    def createAuthenticationFactors(self, expireExistingKeys=False):
        """
        Creates shared authentication factors between Location Service and user, such that we can test the LOCATHE protocol.

        The factors will be of keyTypes:

        PASSWORD_HASH_KEY_TYPE = "Password Hash (KDF)" # String text that identifies the key type.
        SHARED_KEY_KEY_TYPE = "Shared Key" # A generic secret shared key.
        FINGERPRINT_KEY_TYPE = "Fingerprint" # A value that represents, or simulates, a fingerprint template/minutiae.
        FACE_KEY_TYPE =  'Face' # A value that represents, or simulates, a facial pattern for facial recognition.
        IRIS_KEY_TYPE = 'Iris' # A value that represents, or simulates, iris template for iris recognition.
        PIN_KEY_TYPE = 'PIN' # A PIN value, typically numeric.
        PATTERN_KEY_TYPE = 'Pattern' # A value that represents a pattern a user draws on a screen (typically in smartphones).

        Parameters
        ----------
        expireExistingKeys : bool
            True if existing keys of keyType, belonging to each Location Service and user, are to be expired such that new ones are created in place.
            False if existing keys are not to be expired. New keys will be created in addition to existing ones.
        """
        # We will create keys for both agents for each of the keyTypes below.
        keyTypeList = collections.deque([constants.PASSWORD_HASH_KEY_TYPE, constants.SHARED_KEY_KEY_TYPE,
                                         constants.FINGERPRINT_KEY_TYPE, constants.PIN_KEY_TYPE, constants.PATTERN_KEY_TYPE,
                                         constants.FACE_KEY_TYPE, constants.IRIS_KEY_TYPE])
        # Expire existing keys in both databases if such is the selection.
        if expireExistingKeys:
            if debug: print("Expiring keys of keyType: ", keyTypeList)
            locationserviceutility.expireKeysOfType(self.userEntityID, keyTypeList, database=self.locationServiceDatabase)
            locationserviceutility.expireKeysOfType(self.userEntityID, keyTypeList, database=self.userDatabase)


        # In a loop, create a key/factor of each keyType and register them to both the user database and Location Service database.
        # Expire existing keys if the respective argument is True.
        #expirationEpoch = time.time() + constants.DEFAULT_KEY_EXPIRATION_SECONDS
        while keyTypeList:
            nextKeyType = keyTypeList.popleft()
            # We are just going to use random keys here without regard to the actual algorithm utilized to generate the keys in real life.
            key = locationserviceutility.generateNonce()
            salt = b''
            algorithm = 'random(LOCATHE testing)'
            # Register the same key to both databases.
            if debug: print("Registering keys of keyType: ", nextKeyType)
            locationserviceutility.registerKeyToDatabase(self.userEntityID, key, salt, nextKeyType, algorithm, expirationEpoch=time.time() + constants.DEFAULT_KEY_EXPIRATION_SECONDS,
                                                         database=self.locationServiceDatabase)
            locationserviceutility.registerKeyToDatabase(self.userEntityID, key, salt, nextKeyType, algorithm, expirationEpoch=time.time() + constants.DEFAULT_KEY_EXPIRATION_SECONDS,
                                                         database=self.userDatabase)

    def startAgents(self):
        """
        Start the agent simulators.
        """
        # Set instance variables here for the agent simulators.
        # Specify an access policy.
        accessPolicy = "(moncalamariexpedia.com.spendinglimit.level2 OR moncalamariexpedia.com.spendinglimit.level3) AND global.payment.visa"
        #accessPolicy = "moncalamariexpedia.com.spendinglimit.level3"
        authorityList = [self.locationServiceObj.entityID, self.abeAuthorityObj.entityID]
        bnonceLength = 128 # In bits.
        # Initiate the protocol by activating both Location Service agent and User agent simulators.
        # Use multiprocessing for executing both things.
        # The idea is to run the "runProtocol" function from each Location Server and User modules, and they will take it from there.
        locationService = multiprocessing.Process(name='locationService', target=self.locationServiceAgentSimulator.start, args=({'bnonceAccessPolicy':accessPolicy, 'bnonceLengthBits':bnonceLength, 'bnonceAuthorityList':authorityList},))
        #locationService = multiprocessing.Process(name='locationService', target=self.locationServiceAgentSimulator.start)
        locationService.daemon = False
        userAgent = multiprocessing.Process(name='userAgent', target=self.userAgentSimulator.start)
        userAgent.daemon = False

        locationService.start()
        userAgent.start()
        locationService.join()
        userAgent.join()

#        server = multiprocessing.Process(name='server', target=serverjsonnetwork.server)
#        server.daemon = False
#
#        client = multiprocessing.Process(name='client', target=clientjsonnetwork.client)
#        client.daemon = False
#
#        server.start()
#        client.start()
#
#        server.join()
#        client.join()



    def simulateBroadcast_ecdhe(self, locationServiceObj, authorityEntityObj, userAgentObj):
        """
        This function simulates the broadcast/ECDHE phase of the Locathe protocol, wherein a user agent captures an
        ABE-encrypted message and initiates an ECDHE exchange with the Location Service.

        The process should activate each agent simulator in succession. For instance:
        1. Activate the Location Service agent first, such that it initiates advertisement of its Bluetooth service.
        2. Then the user agent simulator reads the advertisement and requests a Bluetooth connection.
        3. Upon finishing the connection, the user agent simulator requests the BNONCE broadcast.
        4. Location Service agent simulator broadcasts BNONCE.
        5. User agent captures BNONCE broadcast, processes it. Computes and sends KEi, Ni.
        6. Location Service receives KEi, Ni. Computes and sends KEr, Nr.
        7. Location Service jumps to state State.TIER1_PRIVACY_AUTHENTICATION.

        Each agent simulator will have, for example, two functions that the protocol simulator will call. One requests
        sending data, and other requests the receipt of data. Each agent will process these functions according to their
        current state in the finite state machine.

        Pick random nonce Nb.
        BNONCE=ABE(AccessPolicy, Nb)
        Sign BNONCE.
        Location service --> Send BNONCE, Sign(BNONCE), Certificate_r --> user agent.

        Parameters
        ----------
        locationServiceObj : object
            Location Service object
        authorityEntityObj : object
            ABE authority object
        userAgentObj : object
            User agent object
        """

        # Set instance variables here for the agent simulators.
        # Specify an access policy.
        self.locationServiceAgentSimulator.accessPolicy = "(moncalamariexpedia.com.spendinglimit.level2 OR moncalamariexpedia.com.spendinglimit.level3) AND global.payment.visa"
        #self.locationServiceAgentSimulator.accessPolicy = "moncalamariexpedia.com.spendinglimit.level3"
        self.locationServiceAgentSimulator.authorityList = [self.locationServiceObj.entityID, self.abeAuthorityObj.entityID]
        # Generate a random token, or nonce, to seed the BNONCE. Use the nonce generator, which is cryptographically secure.
        # Nonce will be a base64-encoded string representation of the nonce.
        # Note that the BNONCE generator function generates its own random nonce. No need to seed it...
        self.locationServiceAgentSimulator.bnonceLength = 128 # In bits.
        nonceLength = 128 # In bits.
        nonce = locationserviceutility.generateNonce(length=nonceLength)
        #self.log.info("BNONCE phase: nonce generated.")
        print("Nonce: ", nonce, "\n of length: ", len(nonce))
#        # ABE-encrypt the nonce using all authorities' keys (including Location Service) and the access policy.
#        bnonce = self.locationServiceObj.generateBnonce(authorityList, accessPolicy, length=nonceLength)
#        self.log.info("BNONCE phase: BNONCE generated.")
#        print("BNONCE: ", bnonce, "\n of length: ", len(bnonce))

        # Initiate the protocol by activating both Location Service agent and User agent simulators.
        # Use multiprocessing for executing both things.
        # The idea is to run the "runProtocol" function from each Location Server and User modules, and they will take it from there.

        self.locationServiceAgentSimulator.processBroadcastEcdheSendKerNr()
#        server = multiprocessing.Process(name='server', target=serverjsonnetwork.server)
#        server.daemon = False
#
#        client = multiprocessing.Process(name='client', target=clientjsonnetwork.client)
#        client.daemon = False
#
#        server.start()
#        client.start()
#
#        server.join()
#        client.join()

    def simulateTier1Authentication(self):
        """
        This function simulates the Tier 1 Privacy Authentication, wherein a user agent authenticates with the Location
        Service based on the user's ABE attributes.

        """
        pass

    def simulateTier2Authentication(self):
        """
        This function simulates the Tier 2 Privacy Authentication, wherein a user agent authenticates with the Location
        Service based on (individual) shared secret keys.

        """
        pass

    def simulateLongTermKeyGeneration(self):
        """
        This is the final phase of Locathe, wherein the parties authenticate all the exchange so far and also (optionally?)
        generate a long term shared key for use in future authentications.

        """
        pass


    def simulateLocathe(self):
        """
        This simulates a run of the Locathe protocol, as if performed by a user agent, an authority/RP agent, and the
        Location Service.

        Reference: http://dx.doi.org/10.1109/ICCNC.2016.7440584

        """
        # TODO: Adjust this for OO!

        self.simulateRegistration()


        self.startAgents()
        #self.simulateBroadcast_ecdhe(self.locationServiceObj, self.abeAuthorityObj, self.userAgentObj)

    #    simulateTier1authentication()

    #    simulateTier2authentication()

    #    simulateLongTermKeyGeneration()

    def createAuthority(self):
        """
        Creates an authority for the simulation if one already does not exist, for all three databases.
        """
        # Create authority (if it yet does not exist), all three databases.
        for database in [self.locationServiceDatabase, self.authorityDatabase, self.userDatabase]:
            if locationserviceutility.createEntity(self.authorityEntityID, self.authorityName, self.authorityEntityType, database):
                self.log.info("Authority %s created, database %s updated.", self.authorityEntityID, database)
            else:
                self.log.info("Authority %s already exists in database %s.", self.authorityEntityID, database)

    def createAttributesAuthority(self):
        """
        Create some attributes for the authority, if they do not exist already. But first create the attributes themselves, if they
        do not yet exist.
        All databases.
        """
        expirationEpoch = time.time() + constants.DEFAULT_ABE_AUTHORITY_KEY_EXPIRATION_SECONDS
        for database in [self.locationServiceDatabase, self.authorityDatabase, self.userDatabase]:
            for attribute in self.authorityAttributes:
                if locationserviceutility.createAttribute(attribute, database = database):
                    self.log.info("Attribute %s created in database %s.", attribute, database)
                else:
                    self.log.info("Attribute %s already exists in database %s.", attribute, database)
                if locationserviceutility.registerEntityAttribute(self.authorityEntityID, attribute, expirationEpoch=expirationEpoch, database = database):
                    self.log.info("Attribute %s for authority %s registered in database %s.", attribute, self.authorityEntityID, database)
                else:
                    self.log.info("Attribute %s for authority % already registered in database %s.", attribute, self.authorityEntityID, database)

    def createUser(self):
        """
        Create the user for this simulation, all databases.
        """
        # Now, create the user.
        # All databases.
        for database in [self.locationServiceDatabase, self.authorityDatabase, self.userDatabase]:
            if locationserviceutility.createEntity(self.userEntityID, self.userName, self.userEntityType, database):
                self.log.info("User %s created, database %s updated.", self.userEntityID, database)
            else:
                self.log.info("User %s already exists in database %s.", self.userEntityID, database)

    def registerUserAttributes(self):
        """
        Register attributes for user.
        All databases (albeit initially the user does not need to know which attributes she has, since she will have the keys nevertheless).
        """
        # Register attributes for user.
        # All databases (albeit initially the user does not need to know which attributes she has, since she will have the keys nevertheless).
        expirationEpoch = time.time() + constants.DEFAULT_ABE_AUTHORITY_KEY_EXPIRATION_SECONDS
        for database in [self.locationServiceDatabase, self.authorityDatabase, self.userDatabase]:
            for attribute in self.userAttributes:
                if locationserviceutility.registerEntityAttribute(self.userEntityID, attribute, expirationEpoch=expirationEpoch, database = database):
                    self.log.info("Attribute %s for user %s registered in database %s.", attribute, self.userEntityID, database)
                else:
                    self.log.info("Attribute %s for user % already registered in database %s.", attribute, self.userEntityID, database)


    def createTotpSecrets(self):
        """
        Create TOTP secret for user.
        Location Service and user databases.

        One previous idea was to modify the functions and database such that entity keys were identified in the database by a pair
        of entity IDs: an owner entity, and a target entity. The idea is that a user could have multiple keys, possibly of the same
        type, to be utilized for different service provides or RPs. For instance, an owner user mrrobot@fsociety.org would have a target
        TOTP secret for amazon.com, and a target TOTP secret for google.com. Each of these target entities could request the TOTP
        identification/authenticationn for themselves, and not rely on the Location Service for a unique TOTP.
        For now, we are not moving with this design, but with the design that has the Location Service be the sole holder of
        keys, such that a user authenticates to the Location Service on behalf of any RP. However, the ABE encrypted message
        in the initial broadcast does utilize ABE keys generated by the authorities/RPs, such that these secret keys are not shared
        among authorities or even the Location Service (this works by means of the authorities/RPs attributes, which are unique to the
        authorities/RPs. An authority/RP can force an authentication for themselves only through the ABE-encrypted broadcast.
        Verify whether there are existing, valid TOTP keys for the user and Location Service. If not, create new ones.
        """
        nowEpoch = time.time()
        userTokenFromUser = locationserviceutility.getEntityCurrentTotpLocatheToken(self.userEntityID, database=self.userDatabase)
        userTokenFromLocationService = locationserviceutility.getEntityCurrentTotpLocatheToken(self.userEntityID, database=self.locationServiceDatabase)
        if (not userTokenFromUser) and (not userTokenFromLocationService): # ~(A + B) = ~A * ~B
            # TOTP keys are not valid in either database. Must then create new ones and register to both databases.
            self.log.info("TOTP keys for user %s not valid or inexistent all databases. Creating new ones.", self.userEntityID)
            totpSecret = locationserviceutility.generateTotpRandomSecret()
            locationserviceutility.registerTotpLocatheSecretSeedToDatabase(self.userEntityID,
                                                                    totpSecret,
                                                                    expirationEpoch=nowEpoch + constants.DEFAULT_KEY_EXPIRATION_SECONDS,
                                                                    database=self.userDatabase)
            locationserviceutility.registerTotpLocatheSecretSeedToDatabase(self.userEntityID,
                                                                    totpSecret,
                                                                    expirationEpoch=nowEpoch + constants.DEFAULT_KEY_EXPIRATION_SECONDS,
                                                                    database=self.locationServiceDatabase)
        elif userTokenFromUser and userTokenFromLocationService:
            # TOTP keys exist in both databases. Now check whether they are the same for consistency and log the results.
            # But keep going.
            self.log.info("TOTP key for entityID %s found in both databases %s and %s.", self.userEntityID, self.userDatabase, self.locationServiceDatabase)
            if userTokenFromUser != userTokenFromLocationService:
                self.log.info("TOTP key for entityID %s is different in databases %s and %s. This is not necessarily an error, but authentication will eventually fail.", self.userEntityID, self.userDatabase, self.locationServiceDatabase)
        else:
            # Valid TOTP key exists in one database, but not in the other. This is inconsistent.
            # Allow the protocol to proceed. Authentication will eventually fail.
            # To correct this, expire all valid TOTP secrets and recreate. Will leave the necessary code below, commented out.
            # Figure out which database has the valid TOTP key for appropriate logging.
            validDatabase = self.userDatabase if userTokenFromUser else self.locationServiceDatabase
            invalidDatabase = self.locationServiceDatabase if userTokenFromUser else self.userDatabase
            self.log.info("TOTP key for entityID %s is VALID in database %s, and INVALID in database %s. Inconsistent, but protocol will proceed and authentication will eventually fail.", self.userEntityID,
                          validDatabase,
                          invalidDatabase)
            # Will not expire TOTP secrets to correct inconsistency. Allow the protocol to fail due to different TOTP seeds.
#==============================================================================
#             locationserviceutility.expireTotpLocatheSecretSeeds(self.userEntityID, database=self.userDatabase)
#             locationserviceutility.expireTotpLocatheSecretSeeds(self.userEntityID, database=self.locationServiceDatabase)
#             self.log.info("TOTP secrets (forcibly) expired.")
#==============================================================================
            # Recall this same function and the secrets should be now created in both databases.
            # Note that if calling this function results in infinite recursion, there is a bug somewhere, since the TOTP
            # secrets are being forcibly expired above.
#==============================================================================
#             self.log.info("Recalling the function to create new TOTP secrets.")
#             self.createTotpSecrets()
#==============================================================================

    def createLocationServicePKIKeys(self):
        """
        Create the Location Service's PKI keys.

        Since the PKI keys are created upon instantiation (to respective files), nothing to do here!
        """
        self.log.info("PKI keys for Location Service available in files.")

    def createAuthorityABEKeys(self, entityID):
        """
        Create the authority's ABE keys (public and secret).

        Since the keys are created upon instantiation of an authority (Location Service included), then there's nothing
        to do here.
        """
        self.log.info("ABE keys for authorities created upon instantiation of authority objects.")

    def createLocationServiceABEKeys(self, entityID):
        """
        Create the Location Service's ABE keys (public and secret).

        Since the keys are created upon instantiation of te Location Service, then there's nothing
        to do here.
        """
        self.log.info("ABE keys for Location Service created upon instantiation of Location Service object.")

    def createABEUserKeys(self, userEntityObj, authorityEntityObj, locationServiceEntityObj):
        """
        Create the user's ABE keys. One user has one ABE key per attribute, issued by the authority that owns that
        attribute. The attribute keys are saved individually to the database

        Parameters
        ----------
        userEntityObj : entity object
            entity object of the user
        authorityEntityObj : entity object
            entity object of the authority who will issue the ABE keys per user attributes
        locationServiceEntityObj : entity object
            entity object of the Location Service
        """

        # Must generate, here, ABE keys from the authority-RP and from the Location Service (for global parameters).
        # The keys will then be retrieved from the authority's and Location Service databases and saved to the user database.
        expirationEpoch = time.time() + constants.DEFAULT_ABE_USER_KEY_EXPIRATION_SECONDS
        abeUserKeysLocationServiceDict, abeUserKeysLocationServiceList = locationServiceEntityObj.locationServiceAuthorityObject.createABEUserKeys(userEntityObj.entityID, expirationEpoch=expirationEpoch, database=userEntityObj.database)
        self.log.info("ABE user secret keys generated for Location Service.")
        abeUserKeysAuthorityDict, abeUserKeysAuthorityList = authorityEntityObj.createABEUserKeys(userEntityObj.entityID, expirationEpoch=expirationEpoch, database=userEntityObj.database)
        self.log.info("ABE user secret keys generated for Authority/RP.")
        # Use the list of individual attribute keys to save them to the user database.
        for key in abeUserKeysLocationServiceList + abeUserKeysAuthorityList:
            result = locationserviceutility.registerKeyToDatabase(userEntityObj.entityID, key, None, constants.ABE_USER_SECRET_KEY_TYPE, "DABE_AW11", expirationEpoch=expirationEpoch, database=userEntityObj.database)
            if result:
                self.log.info("ABE user secret key successfully registered to user database.")
            else:
                self.log.info("ABE user secret key already exists in the database, or problem registering the key.")

    def copyAbePublicKeysFromOriginDatabaseToDestinationDatabase(self, authorityEntityID, fromDatabase, toDatabase):
        """
        Copies an entire tuple from entityKey table from an origin database to a destination database. Tuples belong to
        authorityEntityID.

        The main goal here is to copy ABE authorities' ABE public keys to the Location Service database. All relevant fields
        will be copied verbatim (but the table's primaryKey), obviously considering different values for foreign keys.

        Parameters
        ----------
        authorityEntityID : str
            entityID of the owner of the ABE public keys.
        fromDatabase : str
            filename of the database wherein the authority's ABE public keys are stored.
        toDatabase : str
            filename of the database to which the ABE public keys will be registered or copied.
        """
        locationserviceutility.copyKeysFromOriginDatabaseToDestinationDatabase(authorityEntityID, constants.ABE_AUTHORITY_PUBLIC_KEY_TYPE, fromDatabase, toDatabase)



def simulateLocathe():
    """
    This simulates a run of the Locathe protocol, as if performed by a user agent, an authority/RP agent, and the
    Location Service.

    References
    ----------
        http://dx.doi.org/10.1109/ICCNC.2016.7440584

    """

    print("Simulation starting...")
    # Populate variables with databases and other miscellanea.
    # Create one object of each user agent, authority agent, Location Service.
    locationServiceDatabase= "../" + constants.LOCATION_SERVICE_DATABASE_TEST  #"../locationservicetest.db"
    authorityDatabase =  "../" + constants.LOCATION_SERVICE_AUTHORITY_DATABASE_TEST #"../locationserviceauthoritytest.db"
    userDatabase = "../" + constants.LOCATION_SERVICE_USER_DATABASE_TEST  #"../locationserviceusertest.db"
    authorityEntityID = "moncalamariexpedia.com"

    authorityEntityType = constants.ENTITY_TYPE_AUTHORITY_RP
    authorityName = "Mon Calamari Expedia"
    userEntityID = "gialackbar@live.com"
    userName = "Gial Ackbar"
    userEntityType = constants.ENTITY_TYPE_USER

    authorityAttributes = ["moncalamariexpedia.com.vip.platinum",
                           "moncalamariexpedia.com.vip.prime",
                           "moncalamariexpedia.com.vip.gold",
                           "moncalamariexpedia.com.spendinglimit.level1",
                           "moncalamariexpedia.com.spendinglimit.level2",
                           "moncalamariexpedia.com.spendinglimit.level3"]

    userAttributes = ["moncalamariexpedia.com.vip.platinum",
                      "moncalamariexpedia.com.spendinglimit.level3",
                      "global.payment.visa"]

    locatheSimulatorObj = LocatheSimulator(authorityEntityID,
                                           authorityEntityType,
                                           authorityName,
                                           authorityAttributes,
                                           userEntityID,
                                           userEntityType,
                                           userName,
                                           userAttributes,
                                           locationServiceDatabase,
                                           authorityDatabase,
                                           userDatabase)


    # Run the simulator.
    locatheSimulatorObj.simulateLocathe()


#    simulateRegistration(authorityEntityID, self.authorityName, self.authorityEntityType, self.authorityAttributes,
#                         self.userEntityID, self.userName, self.userEntityType, self.userAttributes,
#                         self.locationServiceDatabase, self.locationServiceDatabase, self.locationServiceDatabase)
#
#    simulateBroadcast_ecdhe()

#    simulateTier1authentication()

#    simulateTier2authentication()

#    simulateLongTermKeyGeneration()

    print("Simulation concluded.")

# Run the simulation.
if __name__ == '__main__':
    simulateLocathe()