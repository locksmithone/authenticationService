"""
Created on Thu May  5 11:02:08 2016

@author: locksmith
"""

from states import State
#import logging
import time
import json
import jsonhelper
import constants
#from netservice import NetService
#import netservice
#import netservicetype
from status import Status
import Crypto.Random.random
import Crypto.Hash.SHA256
import locationserviceutility
import agentsimulator
import hashlib
import collections

# Set this variable to True to allow for printing debugging messages.
debug = True

class UserAgentSimulator(agentsimulator.AgentSimulator):
    """
    This class simulates an Agent running the user agent part of Loc-Auth and interacting with the Location Service.

    This agent simulator is implemented as a Finite-State Machine to run the LOCATHE protocol. The states are
    defined in module states.py.
    """

#    def __init__(self, userAgentObject):
#        """
#        Initialize the object.
#
#        userAgentObject: user agent object already instantiated somewhere else.
#        """
#
#        # Set filename and logging level for log messages, and output formats.
#        FORMAT = "%(asctime)s;%(levelname)s;%(message)s"
#        DATEFORMAT = '%Y-%m-%d %H:%M:%S'
#        formatter = logging.Formatter(fmt=FORMAT, datefmt=DATEFORMAT)
#        self.log = logging.getLogger(__name__)
#        handler = logging.FileHandler(__name__+'.log')
#        self.log.setLevel(logging.DEBUG)
#        handler.setFormatter(formatter)
#        self.log.addHandler(handler)
#
#        self.userAgentObject = useragent.UserAgent(constants.ENTITY_ID_LOCATION_SERVICE) # Does nothing, it is here just to facilitate code completion in Spyder.
#        self.userAgentObject = userAgentObject
#        #self.log.info("Database filename set: %s", self.DATABASE)
#        self.log.info("User Agent Simulator instantiated.")
#
#        self.hybridAbeMultiAuthorityObject, self.globalParameter, self.groupObject = locationserviceutility.createHybridABEMultiAuthorityObject()
#        # The socket server.
#        self.locauthClient = netservice.NetService(netservicetype.NetServiceType.CLIENT, 'localhost')
#        # The agent type, such that some functions can make decisions based on this type.
#        self.agentType = constants.LOCATHE_USER_AGENT_TYPE
#
#        # Resets or initialize variables.
#        self.resetInstanceVariables()

    def resetInstanceVariables(self):
        """
        Resets or reinitializes instance variables for a clean LOCATHE session.
        """
        # Use a list of keyTypes such that the user gather these keyTypes in order to send to the Location Service and fulfill the minimum factorScore.
        super().resetInstanceVariables()
        self.keyTypeList = collections.deque([constants.LOCATHE_JOINT_FACTOR_KEY_KEY_TYPE, constants.PASSWORD_HASH_KEY_TYPE, constants.SHARED_KEY_KEY_TYPE,
                            constants.FINGERPRINT_KEY_TYPE, constants.PIN_KEY_TYPE, constants.PATTERN_KEY_TYPE, constants.FACE_KEY_TYPE, constants.IRIS_KEY_TYPE])

    def getNextKeyAndKeyTypeFactorToAuthenticate(self):
        """
        Returns the next key and keyType the user agent will provide as authentication factor to the Location Service.
        The keyTypes are presented in the order they appear in the instance variable self.keyTypeList. If no more keyTypes are available in
        the list (i.e., all were already presented as factors to the Location Service), then return empty strings for both the key and keyType.

        If, for the current keyType, no secret key is found for the user entityID, the function will restart the procedure for the next keyType
        in the list.

        If more than one key is found for the current keyType, the function will return the first one in the list, which is typically ordered
        by expirationEpoch (ascending order, closest expirationEpoch first).

        Returns
        -------
        byte str, str
            The first key found in the database for the corresponding keyType, closest expirationEpoch. Empty if all keyTypes are exhausted
                and no key was found in the database.
            The next keyType string in the order presented in self.keyTypeList, or empty if no more is available.
        """
        while self.keyTypeList:
            nextKeyType = self.keyTypeList.popleft()
            keyList = locationserviceutility.getEntityKeysOfType(self.agentObject.entityID, nextKeyType, database=self.agentObject.database)
            # Now check whether there are existing keys of nextKeyType, return the first found key if True. Otherwise, try the next keyType.
            if keyList:
                # Let's use the first key in the list, which is the key that will expire the soonest. Convert it to bytes if not already into bytes form.
                key = keyList[0] if not hasattr(keyList[0], 'encode') else keyList[0].encode()
                return key, nextKeyType
            # Else, proceed with the while statement and next keyType in self.keyTypeList.

        # No more keyTypes on which to operate. Leave.
        return b'', ''

    def processStartIdle(self):
        """
        START_IDLE state just passes control to the next state.

        """
        if debug: print("User agent: processStartIdle.")
        if debug: print("User agent: processStartIdle. Reset instance variables.")
        # Reset states.
        self.resetInstanceVariables()
        return Status.START_PROTOCOL, {}

    def processBroadcastEcdheAdvertisementBluetoothLocauthAdvertisement(self):
        """
        Process the BROADCAST_ECDHE_ADVERTISEMENT_BLUETOOTH_LOCAUTH_ADVERTISEMENT state.

        Listens to a service advertisement, Loc-Auth Bluetooth service. If the proper Location Service advertisement is detected, proceed.

        Returns
        -------
        IntNum, dict
            Status of processing this state.
            The response payload received from the other peer, if any.

        Notes
        -----
        Due to limitations in the current Bluetooth architecture, it is not possible to advertise the BNONCE, its signature, and certificate.
        The adverstisement PDU size is about 30 bytes, simply not enough for an ABE-encrypted ciphertext. For Bluetooth, we must adopt the strategy of
        advertising the Locauth service as usually done in Bluetooth architecture. Once a client detects the service, the client requests a connection and
        then the Location Service will send the BNONCE payload (either upon request by the client, or right after the connection is accepted).

        For the purposes of this simulator, utilizing TCP/IP, we will invert the order a bit. First, the Location Service listens for connections. Once a
        connection request is detected and accepted, Location Service will "advertise" itself, simulating a Bluetooth advertisement, and then will proceed
        by sending the BNONCE payload. The rest continues exactly the same as if it were over any type of network medium.
        """
        if debug: print("User agent: processBroadcastEcdheAdvertisementBluetoothLocauthAdvertisement.")
        # For the purposes of this simulation using INET, this state does not really do anything useful. Just receive a mock payload with Bluetooth advertisement
        # data and, if it is the proper one, proceed. Do not enforce SPI checking, because this is the first message and SPIr is unknown to agent, and SPIi is unknown to Location Service.
        advertisementMessage, isHeaderValid = self.receiveMessage(constants.HEADER_EXCHANGE_TYPE_BROADCAST_ECDHE_BLUETOOTH_ADVERTISEMENT, constants.HEADER_MESSAGE_TYPE_REQUEST, enforceSpiCheck=False)
        if not isHeaderValid:
            if debug: print("User agent: invalid header in Location Service advertisement.")
            return Status.INVALID_HEADER, {}
        if advertisementMessage[constants.PAYLOAD_FIELD_NAME_UUID] == constants.LOCAUTH_UUID and advertisementMessage[constants.PAYLOAD_FIELD_NAME_SERVICE_DESCRIPTION] == constants.LOCAUTH_BLUETOOTH_SERVICE_DESCRIPTION:
            if debug: print("User agent: received proper Location Service advertisement. Setting SPIr.")
            # Set the received SPIr from the Location Service. SPIi will be set when user agent sends first message.
            # For Bluetooth, this should be done at the BNONCE receipt phase.
            self.spir = advertisementMessage[constants.HEADER_FIELD_NAME][constants.HEADER_FIELD_NAME_SPI_R]
            # Save the payload for later as IDr, such that we can compute <SignedOctets>.
            self.messageContainer.update({constants.SIGNED_OCTETS_IDR_PAYLOAD: locationserviceutility.extractPayloadFromRawMessage(advertisementMessage[constants.PAYLOAD_FIELD_NAME_RAW_MESSAGE])})
            return Status.SERVICE_ADVERTISEMENT_DETECTED, {}
        else:
            if debug: print("User agent: no proper Location Service advertisement received.")
            return Status.NO_SERVICE_ADVERTISEMENT_DETECTED, {}

    def processBroadcastEcdheReceiveBnonce(self):
        """
        Process the State.BROADCAST_ECDHE_RECEIVE_BNONCE state.

        Receives the BNONCE payload from the Location Service, extracts the Nb, while verifying whether the encryption is correctly authenticated and properly
        signed by the Location Service. If everything checks out, populate the proper variables.

        Returns
        -------
        IntNum, dict
            Status of processing this state.
            The response payload received from the other peer, if any.
        """
        if debug: print("User agent: processBroadcastEcdheReceiveBnonce.")
        # Cannot enforce SPI check yet. The Location Service has not received any message from the user agent, and thus does not know SPIi.
        bnonceMessage, isHeaderValid = self.receiveMessage(constants.HEADER_EXCHANGE_TYPE_BROADCAST_ECDHE_BROADCAST_BNONCE, constants.HEADER_MESSAGE_TYPE_REQUEST, enforceSpiCheck=False)
        if not isHeaderValid:
            return Status.INVALID_HEADER, bnonceMessage

        # Set the received SPIr from the Location Service. SPIi will be set when user agent sends first message.
        # For Bluetooth, this should be done at the BNONCE receipt phase.
        # For non-Bluetooth, set this in the phase at which the first message is received.
        #self.spir = bnonceMessage[constants.HEADER_FIELD_NAME][constants.HEADER_FIELD_NAME_SPI_R]

        self.currentBnonceSerialized = bnonceMessage[constants.PAYLOAD_FIELD_NAME_BNONCE]
        self.currentBnonce = json.loads(self.currentBnonceSerialized, cls=jsonhelper.KeyDecoder)
        self.currentBnonceSignature = bnonceMessage[constants.PAYLOAD_FIELD_NAME_BNONCE_SIGNATURE]
        self.currentBnonceCertificate = bnonceMessage[constants.PAYLOAD_FIELD_NAME_LOCATION_SERVICE_CERTIFICATE]
        if debug: print("User agent: received BNONCE payload. Now verify signature and attempt decrypting...")

        # Verify signature of BNONCE. We need the serialized version of BNONCE to assure there was no change in the order of the inner dicts.
#        validSignature = self.userAgentObject.verify(json.dumps(self.currentBnonce, cls=jsonhelper.KeyEncoder, pairingCurve=self.groupObject.param),
#                                                     self.currentBnonceSignature)
        validSignature = self.agentObject.verify(self.currentBnonceSerialized, self.currentBnonceSignature)
        if validSignature:
            if debug: print("User agent: BNONCE signature is valid.")
            # Signature is ok. Decrypt BNONCE.
            if debug: print("User agent: BNONCE to decrypt is:\n", self.currentBnonce)
            self.currentNb = self.agentObject.abeDecrypt(self.currentBnonce)
            if self.currentNb is not None:
                if debug: print("User agent: BNONCE decryption successful.")
                return Status.BNONCE_RECEIVED, bnonceMessage
        if debug: print("User agent: BNONCE decryption or signature failed.")
        # An invalid BNONCE is either one that failed Location Service signature, or one that could not be decrypted (bad MAC or bad secret keys).
        return Status.INVALID_BNONCE, {}

    def processBroadcastEcdheSendKeiNi(self):
        """
        Process the State.BROADCAST_ECDHE_SEND_KEI_NI state.

        Here, the user agent picks a random value ki and calculates (in ellyptic curve mode) KEi = ki * G, where G is the group generator. It also picks a random
        value Ni, and sends both Ni ad KEi to the Location Service.
        """
        if debug: print("User agent: processBroadcastEcdheSendKeiNi.")
        self.kei, self.ki, self.ni = locationserviceutility.computeKexAndNx()
        # Compute SPIi. SPIr must have already been received with the BNONCE first message.
        self.spii = locationserviceutility.generateSpiRandomValue(constants.SPI_LENGTH_BYTES)
        # Prepare payload and send.
        if debug: print("User agent: sending KEi, Ni...")
        # Send and save the message for later <SignedOctets> computation.
        message = self.sendMessage(constants.HEADER_EXCHANGE_TYPE_SEND_KE_K, constants.HEADER_MESSAGE_TYPE_RESPONSE, {constants.PAYLOAD_FIELD_NAME_KEI:self.kei, constants.PAYLOAD_FIELD_NAME_NI:self.ni})
        self.messageContainer.update({constants.SIGNED_OCTETS_KEI_NI_RAW_MESSAGE: message})

        # -------------- Receive KEr, Nr --------------
        # Now must wait for KEr, Nr from the Location Service.
        if debug: print("User agent: KEi, Ni sent. Waiting for KEr, Nr...")
        response, isHeaderValid = self.receiveMessage(constants.HEADER_EXCHANGE_TYPE_SEND_KE_K, constants.HEADER_MESSAGE_TYPE_REQUEST)
        if not isHeaderValid:
            # Unexpected values within the message header. Leave.
            return Status.INVALID_HEADER, response

        # Header is valid. Proceed.
        # Check whether KEr and Nr are in the payload.
        if (constants.PAYLOAD_FIELD_NAME_KER in response) and (constants.PAYLOAD_FIELD_NAME_NR in response):
            if debug: print("User agent: received KEr, Nr.")
            self.ker = response[constants.PAYLOAD_FIELD_NAME_KER]
            self.nr = response[constants.PAYLOAD_FIELD_NAME_NR]
            # Save the message for later <SignedOctets> computation.
            self.messageContainer.update({constants.SIGNED_OCTETS_KER_NR_RAW_MESSAGE: response[constants.PAYLOAD_FIELD_NAME_RAW_MESSAGE]})

            # Now calculate the final part of ECDHE, i.e., the shared secrets.
            if debug: print("User agent: proceeding to compute shared secrets.")
            self.computeEcdheSecrets()
            # Done with Broadcast phase.
            return Status.SHARED_SECRETS_COMPUTED, {}

        else:
            if debug: print("User agent: did not receive KEr, Nr.")
            return Status.INVALID_KER_NR, response

#    def computeEcdheSecrets(self):
#        """
#        Compute the ECDHE secrets, such as shared secret session keys according to the ellyptic-curve Diffie-Hellman key exchange algorithm.
#
#        Common:
#        SharedSecret = ki * kr * G = ki * KEr = kr * KEi
#        KeySeed = prf(Ni | Nr, SharedSecret)
#        {SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr | … } = prf+(KeySeed, Ni | Nr | SPIi | SPIr)
#        """
#        if debug: print("User agent: computeEcdheSecrets.")
#        outputLengthBits = constants.SYMMETRIC_KEY_LENGTH_BITS * 6 # 6 keys of 256 bits each.
#        self.sharedSecret, keyMaterial = locationserviceutility.computeEcdheSecrets(self.ki, self.ker, self.ni, self.nr, self.spii, self.spir, outputLengthBits, hashFunction=Crypto.Hash.SHA256)
#        if debug: print("User agent: sharedSecret: ", self.sharedSecret)
#        if debug: print("User agent: keyMaterial: ", keyMaterial)
#        # Extract the secret session keys from the keyMaterial. Order is imperative.
#        self.skai = keyMaterial[:31]
#        self.skar = keyMaterial[32:63]
#        self.skei = keyMaterial[64:95]
#        self.sker = keyMaterial[96:127]
#        self.skpi = keyMaterial[128:159]
#        self.skpr = keyMaterial[160:191]
#        if debug: print("User agent: shared secrets computed.")


    def processConnectToService(self, maxAttempts=1):
        """
        Connects the user agent to the Location Service server.
        """
        connectionAttempts = 0
        if debug: print("User agent: processConnectToService.")
        self.socketServer.createSocket()
        while connectionAttempts < maxAttempts:
            try:
                self.socketServer.connectToDestination()
                if debug: print("User agent: connected to Location Service.")
                self.log.info("User agent: socket created. Request connection to Location Service on port: %s", self.socketServer.destPort)
                # TODO: Must treat timeouts and other errors here in the future.
                return Status.CONNECTED, {}

            except Exception as e:
                connectionAttempts += 1
                self.log.exception("Exception in connecting to Location Service.")
                if debug: print("Exception in connecting to Location Service: ", e)
                if debug: print("Attempt# {}".format(connectionAttempts))
                # Delay next attempt a bit.
                time.sleep(1)

        return Status.CONNECTION_ERROR, {}

    def processTier1PrivacyAuthentication(self):
        """
        Do Tier_1_Privacy_Authentication.
        """
        if debug: print("User agent: processTier1PrivacyAuthentication.")
        if debug: print("Current messageContainer:\n", self.messageContainer)

        # At this tier, the IDi is anonymous. Add it here to messageContainer.
        self.messageContainer.update({constants.SIGNED_OCTETS_IDI_PAYLOAD_TIER1:locationserviceutility.buildAnonymousIdPayload()})
        authTier1iLocal = self.computeAuthTier1i()
        if debug: print("User agent: authTier1i: ", authTier1iLocal, "\nLength: ", len(authTier1iLocal))
        # Send the encrypted message with the AUTH payload.
        message = self.sendEncryptedMessage(constants.HEADER_EXCHANGE_TYPE_AUTH1, constants.HEADER_MESSAGE_TYPE_RESPONSE,
                                            {constants.PAYLOAD_FIELD_NAME_AUTH_TIER1_I: authTier1iLocal})
        if debug: print("User agent: AUTH_TIER1i sent:\n", message)
        # Now, receive the AUTH_TIER1_r from the Location Service (responder).
        response, isHeaderValid = self.receiveEncryptedMessage(constants.HEADER_EXCHANGE_TYPE_AUTH1, constants.HEADER_MESSAGE_TYPE_REQUEST)
        # Validate header.
        if not isHeaderValid:
            # Unexpected values within the message header. Leave.
            return Status.INVALID_HEADER, response
        # Header is valid. Verify whether AUTH_TIER1_r is valid by computing it here, comparing the hashes of each, and also validating its
        # signature.
        authTier1rLocal = self.computeAuthTier1r()
        # Hey, do not compare signatures this way! Although the final effect may be the same, it is not normal practice.
        # Compare the signature of the *received* payload, not the local, computed one.
#        # Fetch the signature and validate it.
#        validSignature = self.agentObject.verify(authTier1rLocal, response[constants.PAYLOAD_FIELD_NAME_AUTH_TIER1_R_SIGNATURE])
#        if not validSignature:
#            if debug: print("User agent: invalid AUTH_TIER1r signature")
#            self.log.error("Invalid AUTH_TIER1r signature.")
#            return Status.INVALID_TIER1_PAYLOAD, response
        ## Fetch the AUTH_TIER1_r value from the Location Service message.
        authTier1rReceived = response[constants.PAYLOAD_FIELD_NAME_AUTH_TIER1_R]
        if debug: print("User agent: authTier1rLocal (expected):\n", authTier1rLocal)
        if debug: print("User agent: authTier1rReceived:\n", authTier1rReceived)
        
        # Fetch the signature and validate it.
        validSignature = self.agentObject.verify(authTier1rReceived, response[constants.PAYLOAD_FIELD_NAME_AUTH_TIER1_R_SIGNATURE])
        if not validSignature:
            if debug: print("User agent: invalid AUTH_TIER1r signature")
            self.log.error("Invalid AUTH_TIER1r signature.")
        else:
            if debug: print("User agent: valid AUTH_TIER1r signature")
            self.log.error("Valid AUTH_TIER1r signature.")
#            return Status.INVALID_TIER1_PAYLOAD, response
        # Do not return yet if signature is invalid. Check the payload too, such that the other party, or an attacker, does not know exactly
        # what failed.
        
        # Compare the values and log error if their hashes differ, or if the signature was invalid. Use hashes to illustrante timing attack mitigation.
        # In production code, if the log identifies, separately, signature or payload failure, then it is useless to avoid separation of returns here.
        equalAuthPayloads = Crypto.Hash.SHA256.new(authTier1rLocal).digest() == Crypto.Hash.SHA256.new(authTier1rReceived).digest()
        if not equalAuthPayloads:
            if debug: print("User agent: AUTH_TIER1 values differ.")
            self.log.error("AUTH_TIER1 values do not match.")
        if not validSignature or not equalAuthPayloads:
            return Status.INVALID_TIER1_PAYLOAD, response
        else:
            return Status.TIER1_PHASE_OK, response

    def processTier2PrivacyAuthentication(self):
        """
        Do Tier_2_Privacy_Authentication.

        Authentication Tier 2:
        Spwd = prf(“LocAuth Tier_2”, UserKey)
        Kpwd = prf+(Ni | Nr, Spwd)
        s = random
        ENONCE = Encrypt_Kpwd(s)  // non-authenticated.
        GE = s*G + SharedSecret
        AUTH_TIER2_i=prf(prf+(Ni | Nr, “LocAuth Tier_2” | Nb), <SignedOctets_i> | KEr)
        Create pair LSK_i, LPK_i // (LPK_i = LSK_i * GE)

        Send from Initiator to Responder: SK_e,ai(ENONCE, IDi, LPK_i, AUTH_TIER2_i)

        Verify IDi, AUTH_TIER2_i.
        Spwd = prf(“LocAuth Tier_2”, UserKey)
        Kpwd = prf+(Ni | Nr, Spwd)
        GE = s*G + SharedSecret
        Create pair LSK_r, LPK_r // (LPK_r = LSK_r * GE)

        Send Responder to Initiator: SK_e,ar(IDr, LPK_r, [additional auth. requests])

        Proposed modification:

        Initiator sends to Responder:
        SK_ei(ENONCE, keyType, Idi, AUTH_TIER2_i)
        Update sAuth.

        Responder sends to Initiator:
        SE_er(Idr, AUTH_TIER2_r, sign(AUTH_TIER2_r), currentFactorScore, minimumScore)
        Update sAuth.

        Initiator sends to Responder: (repeat until currentFactorScore => minimumScore)
        SK_ei(ENONCE, keyType)
        Update sAuth.

        Responder sends to Initiator:
        SK_er(currentFactorScore, minimumScore)
        Update sAuth.

        Final round:
        Initiator sends to Responder:
        SK_ei(LPKi)

        Responder sends to Initiator:
        SK_er(LPKr)

        Proceed to Exchange Authentication/LTK Generation.
        """
        # ---------- First Round ----------
        # Initiator sends to Responder:
        # SK_ei(ENONCE, keyType, Idi, AUTH_TIER2_i)
        # Responder sends to Initiator:
        # SE_er(Idr, AUTH_TIER2_r, sign(AUTH_TIER2_r), currentFactorScore, minimumScore)

        # Construct an IDi payload and put it into the messageContainer. Since we are not using separate payloads here, but a single dictionary with
        # all data, we must simulate a raw payload containing only the IDi data for Tier2.
        idiPayload = self.constructIDiPayload({constants.PAYLOAD_FIELD_NAME_ID_I: self.agentObject.entityID})
        self.messageContainer.update({constants.SIGNED_OCTETS_IDI_PAYLOAD_TIER2:idiPayload})
        # Compute the AUTH_TIER2_i value.
        authTier2i = self.computeAuthTier2i()
        # Pick a keyType, its related secret key, and compute ENONCE.
        key, keyType = self.getNextKeyAndKeyTypeFactorToAuthenticate()
        # If key is an empty string, then no keys were found for all keyTypes in the list of keyTypes. Cannot authenticate, therefore leave.
        if not key:
            return Status.USER_KEY_NOT_FOUND, {}
        # Compute kpwd, ENONCE, and update appropriate instance variables.
        eNonce = self.computeKpwdThenEnonceUpdateSauthAndCurrentFactorScore(key, keyType)
        # Finally, send the message with ENONCE, keyType, IDi, and AUTH_TIER2_i to Location Service.
        message = self.sendEncryptedMessage(constants.HEADER_EXCHANGE_TYPE_AUTH2, constants.HEADER_MESSAGE_TYPE_RESPONSE,
                                            {constants.PAYLOAD_FIELD_NAME_AUTH_TIER2_I: authTier2i,
                                             constants.PAYLOAD_FIELD_NAME_ENONCE: eNonce,
                                             constants.PAYLOAD_FIELD_NAME_AUTHENTICATION_KEY_TYPE: keyType,
                                             constants.PAYLOAD_FIELD_NAME_ID_I: self.agentObject.entityID})
        if debug: print("User agent: AUTH_TIER2i, ENONCE, keyType, IDi sent:\n", message)

        # Now expect a message from the user agent containing IDr, AUTH_TIER2_r, its signature, currentFactorScore, minimumScore.
        response, isHeaderValid = self.receiveEncryptedMessage(constants.HEADER_EXCHANGE_TYPE_AUTH2, constants.HEADER_MESSAGE_TYPE_REQUEST)
        # Validate header.
        if not isHeaderValid:
            # Unexpected values within the message header. Leave.
            self.log.error("Invalid header.")
            return Status.INVALID_HEADER, response
        # Header is valid. Assert the necessary information is contained in the message.
        if constants.PAYLOAD_FIELD_NAME_AUTH_TIER2_R not in response or constants.PAYLOAD_FIELD_NAME_ID_R not in response or \
        constants.PAYLOAD_FIELD_NAME_AUTH_TIER2_R_SIGNATURE not in response or \
        constants.PAYLOAD_FIELD_NAME_CURRENT_FACTOR_SCORE not in response or \
        constants.PAYLOAD_FIELD_NAME_MINIMUM_FACTOR_SCORE not in response:
            self.log.error("Missing necessary info in message (AUTH_TIER2_R, signature, ID_R, currentFactorScore, minimumFactorScore).")
            return Status.INVALID_TIER2_PAYLOAD, response

        # Verify whether AUTH_TIER2_r is valid by computing it here, comparing the hashes of each, and also validating its
        # signature.
        authTier2rLocal = self.computeAuthTier2r()
        # Fetch the AUTH_TIER2_r value from the Location Service message.
        authTier2rReceived = response[constants.PAYLOAD_FIELD_NAME_AUTH_TIER2_R]
        if debug: print("User agent: authTier2rLocal (expected):\n", authTier2rLocal)
        if debug: print("User agent: authTier2rReceived:\n", authTier2rReceived)

        # Fetch the signature and validate it.
        validSignature = self.agentObject.verify(authTier2rReceived, response[constants.PAYLOAD_FIELD_NAME_AUTH_TIER2_R_SIGNATURE])
        if not validSignature:
            if debug: print("User agent: invalid AUTH_TIER2r signature")
            self.log.error("Invalid AUTH_TIER2r signature.")
            return Status.INVALID_TIER2_PAYLOAD, response
        else:
            if debug: print("User agent: valid AUTH_TIER2r signature")
            self.log.error("Valid AUTH_TIER2r signature.")
        
        # Note: Look at the return code style at Tier1 phase function above, for invalid signature and payload.
        # The return only happens at the end of the two if tests. Why did I not follow the same style here?
        
        # Compare the values and log error if their hashes differ, or if the signature was invalid. Use hashes to illustrante timing attack mitigation.
        # In production code, if the log identifies, separately, signature or payload failure, then it is useless to avoid separation of returns here.
        equalAuthPayloads = hashlib.sha256(authTier2rLocal).digest() == hashlib.sha256(authTier2rReceived).digest()
        if not equalAuthPayloads:
            if debug: print("User agent: AUTH_TIER2 values differ.")
            self.log.error("AUTH_TIER2 values do not match.")
            return Status.INVALID_TIER2_PAYLOAD, response
        # The payload is ok. Now let's check what Location Service says about currentFactorScore and minimumFactorScore and decide
        # whether to go to state to furnish additional authentication factors or to state to compute LPK/LSK.
        if response[constants.PAYLOAD_FIELD_NAME_CURRENT_FACTOR_SCORE] >= response[constants.PAYLOAD_FIELD_NAME_MINIMUM_FACTOR_SCORE]:
            # Location Service says the current factor score is >= minimum. No more factors needed; the Service will be waiting for LPKi.
            return Status.MINIMUM_FACTOR_SCORE_FULFILLED, response
        else:
            # Location Service says it needs more factors, or will not authenticate user. Proceed to proper state to give it more factors.
            return Status.ADDITIONAL_AUTHENTICATION_FACTORS_NEEDED, response


    def processTier2PrivacyAuthenticationAdditionalAuthenticationFactors(self):
        """
        In this state, provide the Location Service with more authentication factors, if existent, until the current factor score fulfills the
        minimum needed factor score, as informed by the Location Service through the messages.

        Obviously, the user agent can track the current score value and decide by itself when it has been fulfilled without waiting for the
        Location Service to inform of such. However, the Location Service assumes the correct score information and respective decision belongs
        to the Location Service only, and thus expects the user agent to wait for confirmation that the minimum authentication factor
        has been fulfilled and LPK/LSK pair is to be exchanged.
        """
        # Initiator sends to Responder: (repeat until currentFactorScore => minimumScore)
        # SK_ei(ENONCE, keyType)
        # Pick a keyType, its related secret key, and compute ENONCE.
        key, keyType = self.getNextKeyAndKeyTypeFactorToAuthenticate()
        # If key is an empty string, then no keys were found for all keyTypes in the list of keyTypes. Cannot authenticate, therefore leave.
        if not key:
            return Status.USER_KEY_NOT_FOUND, {}
        # Compute kpwd, ENONCE, and update appropriate instance variables (sAuth in particular).
        eNonce = self.computeKpwdThenEnonceUpdateSauthAndCurrentFactorScore(key, keyType)
        # Finally, send the message with ENONCE, keyType to Location Service.
        message = self.sendEncryptedMessage(constants.HEADER_EXCHANGE_TYPE_AUTH2, constants.HEADER_MESSAGE_TYPE_RESPONSE,
                                            {constants.PAYLOAD_FIELD_NAME_ENONCE: eNonce,
                                             constants.PAYLOAD_FIELD_NAME_AUTHENTICATION_KEY_TYPE: keyType})
        if debug: print("User agent: ENONCE, keyType:\n", message)

        # Now expect a message from the user agent containing IDr, AUTH_TIER2_r, its signature, currentFactorScore, minimumScore.
        response, isHeaderValid = self.receiveEncryptedMessage(constants.HEADER_EXCHANGE_TYPE_AUTH2, constants.HEADER_MESSAGE_TYPE_REQUEST)
        # Validate header.
        if not isHeaderValid:
            # Unexpected values within the message header. Leave.
            self.log.error("Invalid header.")
            return Status.INVALID_HEADER, response
        # Header is valid. Assert the necessary information is contained in the message.
        if constants.PAYLOAD_FIELD_NAME_CURRENT_FACTOR_SCORE not in response or constants.PAYLOAD_FIELD_NAME_MINIMUM_FACTOR_SCORE not in response:
            self.log.error("Missing necessary info in message (currentFactorScore, minimumFactorScore).")
            return Status.INVALID_TIER2_PAYLOAD, response
        # The payload is ok. Now let's check what Location Service says about currentFactorScore and minimumFactorScore and decide
        # whether to go to state to furnish additional authentication factors or to state to compute LPK/LSK.
        if response[constants.PAYLOAD_FIELD_NAME_CURRENT_FACTOR_SCORE] >= response[constants.PAYLOAD_FIELD_NAME_MINIMUM_FACTOR_SCORE]:
            # Location Service says the current factor score is >= minimum. No more factors needed; the Service will be waiting for LPKi.
            if debug: print("User agent: Authenticated!")
            return Status.MINIMUM_FACTOR_SCORE_FULFILLED, response
        else:
            # Location Service says it needs more factors, or will not authenticate user. Proceed to proper state to give it more factors.
            return Status.ADDITIONAL_AUTHENTICATION_FACTORS_NEEDED, response

    def processTier2PrivacyAuthenticationLPK_LSK(self):
        """
        Do Tier_2_Privacy_Authentication compute/send/receive LPK/LSK keys.
        """
        # ---------- Final Round ----------
        # Initiator sends to Responder:
        # SK_ei(LPKi)
        # Compute LSK/LPK pair and GE.
        self.computeLskLpkPairAndGe()
        message = self.sendEncryptedMessage(constants.HEADER_EXCHANGE_TYPE_AUTH2, constants.HEADER_MESSAGE_TYPE_RESPONSE,
                                            {constants.PAYLOAD_FIELD_NAME_LPKI: self.lpki})


        # Responder sends to Initiator:
        # SK_er(LPKr)
        response, isHeaderValid = self.receiveEncryptedMessage(constants.HEADER_EXCHANGE_TYPE_AUTH2, constants.HEADER_MESSAGE_TYPE_REQUEST)
        if not isHeaderValid:
            # Unexpected values within the message header. Leave.
            self.log.error("Invalid header.")
            return Status.INVALID_HEADER, response
        # Assert LPKr was received.
        if constants.PAYLOAD_FIELD_NAME_LPKR not in response:
            self.log.error("Missing necessary info in message (LPKr).")
            return Status.INVALID_TIER2_PAYLOAD, response
        # Store the LPKr value received from user agent initiator.
        self.lpkr = response[constants.PAYLOAD_FIELD_NAME_LPKR]
        return Status.TIER2_PHASE_OK, response

    def processExchangeAuthenticationJointFactorKeyGeneration(self):
        """
        Do final Exchange Authentication, JointFactorKey generation.
        Here, we simply:
            1. Compute AUTHi, AUTHr, JFK (it is all in the same function).
            2. Send AUTHi to Location Service.
            3. Receive AUTHr from Location Service.
            4. Compare local AUTHr and received AUTHr.
            5. If OK, done. Register/save JFK if that is the choice and go to handoff stage.

        The conditions to register JFK can be, for instance, only register JointFactorKey if no other valid key is present. If full
        authentication was obtained (no anonymous, Tier 1 authentication only).
        """
        # Compute AUTHi and send it to Location Service. AUTHr and JFK will also be computed, since the same function computes all.
        authi, authrLocal, jointFactorKey = self.computeFinalAuthAndJointFactorKey(self.agentObject.entityID)
        message = self.sendEncryptedMessage(constants.HEADER_EXCHANGE_TYPE_JFK_HANDOFF, constants.HEADER_MESSAGE_TYPE_RESPONSE,
                                            {constants.PAYLOAD_FIELD_NAME_AUTH_I: authi})
        # Receive AUTHr from Location Service and compare with locally computed one.
        response, isHeaderValid = self.receiveEncryptedMessage(constants.HEADER_EXCHANGE_TYPE_JFK_HANDOFF, constants.HEADER_MESSAGE_TYPE_REQUEST)
        if not isHeaderValid:
            self.log.error("Invalid header.")
            return Status.INVALID_HEADER, response
        # Assert AUTHr is in the message.
        if constants.PAYLOAD_FIELD_NAME_AUTH_R not in response:
            self.log.error("Missing necessary info in message (AUTHr)")
            return Status.INVALID_JFK_AUTH_PAYLOAD, response
        # Fetch the AUTHr value for later comparison.
        authrReceived = response[constants.PAYLOAD_FIELD_NAME_AUTH_R]
        # Verify AUTHr.
        if hashlib.sha256(authrReceived).digest() != hashlib.sha256(authrLocal).digest():
            if debug: print("User agent: AUTHr values differ.")
            self.log.error("AUTHr values do not match.")
            return Status.INVALID_JFK_AUTH_PAYLOAD, response
        # AUTHr matches. We are done. Process the JointFactorKey (register it, or not) and end the protocol (handoff).
        # Here we have a few options. If there is a valid JFK in the database, we may choose not to register another one.
        # Or, expire the old one, register the new.
        # Or, register the new one and allow the old one to remain valid.
        # If registration fails for some reason, signal that through the status message.
        if not self.registerJointFactorKey(self.agentObject.entityID, jointFactorKey, expireExistingJFKs=True):
            return Status.AUTHENTICATION_OK_JFK_NOT_REGISTERED_HANDOFF, message
        else:
            return Status.AUTHENTICATION_OK_JFK_REGISTERED_HANDOFF, message

    def processAuthenticatedHandoff(self):
        """
        Process the State.AUTHENTICATED_HANDOFF state.

        Currently, the user agent simulator does nothing in this state. The AUTHi has been sent previously, the AUTHr has been received
        and validated in the previous state ExchangeAuthenticationJointFactorKeyGeneration, and the JFK has (or not) been registered.
        Nothing to do here, but as future work, we may do handoff to RP or similar.

        Returns
        -------
        IntNum, dict
            Status of processing this state.
            The response payload received from the other peer, if any.
        """
        return Status.HANDED_OFF, {}

    def runProtocol(self, payloadData):
        """
        Runs the LOCATHE protocol, according to the message, if any, and the current state.

        Parameters
        ----------
        payloadData : dict
            Data to be processed by the protocol, possibly empty, typically received from the other peer. It should be
            already deserialized.

        Returns
        -------
        dict
            Data response to be sent to other peer, if any response is needed. Must be serialized before sending through network.
        """
        if debug: print("User agent: runProtocol.")
        response = payloadData

        while True:

            self.log.info("Processing state: %s", self.currentState)
            if debug: print("User agent: processing state: ", self.currentState)

            # -------------------------------------------------
            if self.currentState == State.START_IDLE:
                self.processStartIdle()
                # Set next state.
                self.currentState = State.CONNECT_TO_SERVICE

            # -------------------------------------------------
            elif self.currentState == State.CONNECT_TO_SERVICE:
                status, response = self.processConnectToService(maxAttempts=10)
                if status == Status.CONNECTED:
                    if debug: print("User agent: CONNECTED to Location Service.")
                    # Set next state.
                    self.currentState = State.BROADCAST_ECDHE_ADVERTISEMENT_BLUETOOTH_LOCAUTH_ADVERTISEMENT
                else:
                    if debug: print("User agent: did not CONNECT to Location Service. Exiting...")
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT

            # -------------------------------------------------
            elif self.currentState == State.BROADCAST_ECDHE_ADVERTISEMENT_BLUETOOTH_LOCAUTH_ADVERTISEMENT:
                status, response = self.processBroadcastEcdheAdvertisementBluetoothLocauthAdvertisement()
                if status == Status.SERVICE_ADVERTISEMENT_DETECTED:
                    if debug: print("User agent: SERVICE_ADVERTISEMENT_DETECTED.")
                    self.currentState = State.BROADCAST_ECDHE_RECEIVE_BNONCE
                else:
                    if debug: print("User agent: did not SERVICE_ADVERTISEMENT_DETECTED. Stay at same state.")
                    self.currentState = State.BROADCAST_ECDHE_ADVERTISEMENT_BLUETOOTH_LOCAUTH_ADVERTISEMENT

            # -------------------------------------------------
            elif self.currentState == State.BROADCAST_ECDHE_RECEIVE_BNONCE:
                status, response = self.processBroadcastEcdheReceiveBnonce()
                if status == Status.BNONCE_RECEIVED:
                    if debug: print("User agent: BNONCE_RECEIVED.")
                    self.currentState = State.BROADCAST_ECDHE_SEND_KEI_NI
                elif status == Status.INVALID_BNONCE:
                    if debug: print("User agent: INVALID_BNONCE.")
                    # TODO: Choose what to do here in case of bad BNONCE. Stop immediately, or proceed to send KEi, Ni, which will eventually fail.
                    # If we fail immediately, then an attacker might attempt to use the user agent as an online decryption oracle.
                    # If we delay fail, we insert a time penalty to an attacker.
                    #self.currentState = State.BROADCAST_ECDHE_RECEIVE_BNONCE
                    #self.currentState = State.BROADCAST_ECDHE_SEND_KEI_NI
                    #self.currentState = State.START_IDLE
                    # Let's just give up and close the connection for now.
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT


            # -------------------------------------------------
            elif self.currentState == State.BROADCAST_ECDHE_SEND_KEI_NI:
                status, response = self.processBroadcastEcdheSendKeiNi()
                if status == Status.INVALID_KER_NR:
                    if debug: print("User agent: INVALID_KER_NR. Go back to same state?")
                    # TODO: fail or attempt again?
                    #self.currentState = State.BROADCAST_ECDHE_SEND_KEI_NI
                    # Let's just give up and close the connection for now.
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT
                elif status == Status.SHARED_SECRETS_COMPUTED:
                    if debug: print("User agent: SHARED_SECRETS_COMPUTED.")
                    self.currentState = State.TIER1_PRIVACY_AUTHENTICATION
                elif Status.INVALID_HEADER:
                    if debug: print("User agent: invalid header values.")
                    #self.currentState = State.BROADCAST_ECDHE_ADVERTISEMENT_BLUETOOTH_LOCAUTH_ADVERTISEMENT
                    # Let's just give up and close the connection for now.
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT
                else:
                    #self.currentState = State.START_IDLE
                    # Let's just give up and close the connection.
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT

            # -------------------------------------------------
            elif self.currentState == State.TIER1_PRIVACY_AUTHENTICATION:
                status, response = self.processTier1PrivacyAuthentication()
                if status == Status.TIER1_PHASE_OK:
                    self.currentState = State.TIER2_PRIVACY_AUTHENTICATION
                elif status == Status.INVALID_TIER1_PAYLOAD or status == Status.INVALID_HEADER:
                    if debug: print("User agent: State.TIER1_PRIVACY_AUTHENTICATION: header or payload error/invalid.")
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT
                else:
                    if debug: print("User agent: Unknown status.")
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT
                #sys.exit(0)

            # -------------------------------------------------
            elif self.currentState == State.TIER2_PRIVACY_AUTHENTICATION:
                status, response = self.processTier2PrivacyAuthentication()
                if status == Status.MINIMUM_FACTOR_SCORE_FULFILLED:
                    self.log.info("User agent: Minimum factor score fulfilled. Go to LPK/LSK state.")
                    self.currentState = State.TIER2_PRIVACY_AUTHENTICATION_LPK_LSK
                elif status == Status.ADDITIONAL_AUTHENTICATION_FACTORS_NEEDED:
                    self.log.info("User agent: Additional authentication factors needed.")
                    self.currentState = State.TIER2_PRIVACY_AUTHENTICATION_ADDITIONAL_AUTHENTICATION_FACTORS
                elif status == Status.INVALID_HEADER or status == Status.INVALID_TIER2_PAYLOAD or status == Status.USER_KEY_NOT_FOUND:
                    if debug: print("User agent - State.TIER2_PRIVACY_AUTHENTICATION: header or payload or user key not found error.")
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT
                else:
                    if debug: print("User agent - State.TIER2_PRIVACY_AUTHENTICATION: Unknown status.")
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT

            # -------------------------------------------------
            elif self.currentState == State.TIER2_PRIVACY_AUTHENTICATION_ADDITIONAL_AUTHENTICATION_FACTORS:
                status, response = self.processTier2PrivacyAuthenticationAdditionalAuthenticationFactors()
                if status == Status.MINIMUM_FACTOR_SCORE_FULFILLED:
                    self.log.info("User agent: Minimum factor score fulfilled. Go to LPK/LSK state.")
                    self.currentState = State.TIER2_PRIVACY_AUTHENTICATION_LPK_LSK
                elif status == Status.ADDITIONAL_AUTHENTICATION_FACTORS_NEEDED:
                    self.log.info("User agent: Additional authentication factors needed.")
                    self.currentState = State.TIER2_PRIVACY_AUTHENTICATION_ADDITIONAL_AUTHENTICATION_FACTORS
                elif status == Status.INVALID_HEADER or status == Status.INVALID_TIER2_PAYLOAD or status == Status.USER_KEY_NOT_FOUND:
                    if debug: print("User agent: State.TIER2_PRIVACY_AUTHENTICATION_ADDITIONAL_AUTHENTICATION_FACTORS: header or payload or user key not found error.")
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT
                else:
                    if debug: print("User agent: State.TIER2_PRIVACY_AUTHENTICATION_ADDITIONAL_AUTHENTICATION_FACTORS: Unknown status.")
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT

            # -------------------------------------------------
            elif self.currentState == State.TIER2_PRIVACY_AUTHENTICATION_LPK_LSK:
                status, response = self.processTier2PrivacyAuthenticationLPK_LSK()
                if status == Status.TIER2_PHASE_OK:
                    self.log.info("User agent: TIER2 phase done.")
                    self.currentState = State.EXCHANGE_AUTHENTICATION_JOINT_FACTOR_KEY_GENERATION
                elif status == Status.INVALID_HEADER or status == Status.INVALID_TIER2_PAYLOAD:
                    if debug: print("User agent: State.TIER2_PRIVACY_AUTHENTICATION_ADDITIONAL_AUTHENTICATION_FACTORS: header or payload error.")
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT
                else:
                    if debug: print("User agent: State.TIER2_PRIVACY_AUTHENTICATION_ADDITIONAL_AUTHENTICATION_FACTORS: Unknown status.")
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT


            # -------------------------------------------------
            elif self.currentState == State.EXCHANGE_AUTHENTICATION_JOINT_FACTOR_KEY_GENERATION:
                status, response = self.processExchangeAuthenticationJointFactorKeyGeneration()
                if status == Status.INVALID_JFK_AUTH_PAYLOAD or status == Status.INVALID_HEADER:
                    if debug: print("User agent: EXCHANGE_AUTHENTICATION_JOINT_FACTOR_KEY_GENERATION: Invalid header or invalid payload.")
                    self.log.info("User agent: EXCHANGE_AUTHENTICATION_JOINT_FACTOR_KEY_GENERATION: Invalid header or invalid payload.")
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT
                elif status == Status.AUTHENTICATION_OK_JFK_NOT_REGISTERED_HANDOFF:
                    if debug: print("User agent: EXCHANGE_AUTHENTICATION_JOINT_FACTOR_KEY_GENERATION: Authenticated, JFK *not* registered.")
                    self.log.info("User agent: EXCHANGE_AUTHENTICATION_JOINT_FACTOR_KEY_GENERATION: Authenticated, JFK *not* registered.")
                    self.currentState = State.AUTHENTICATED_HANDOFF
                elif status == Status.AUTHENTICATION_OK_JFK_REGISTERED_HANDOFF:
                    if debug: print("User agent: EXCHANGE_AUTHENTICATION_JOINT_FACTOR_KEY_GENERATION: Authenticated, JFK registered.")
                    self.log.info("User agent: EXCHANGE_AUTHENTICATION_JOINT_FACTOR_KEY_GENERATION: Authenticated, JFK registered.")
                    self.currentState = State.AUTHENTICATED_HANDOFF
                else:
                    if debug: print("User agent: EXCHANGE_AUTHENTICATION_JOINT_FACTOR_KEY_GENERATION: Unknown status.")
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT


            # -------------------------------------------------
            elif self.currentState == State.AUTHENTICATED_HANDOFF:
                status, response = self.processAuthenticatedHandoff()
                if status == Status.HANDED_OFF:
                    self.log.info("User agent: LOCATHE authentication completed. Handing off to RP service.")
                    if debug: print("User agent: LOCATHE authentication completed. Handing off to RP service.")
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT
                else:
                    self.log.info("User agent: Unexpected status. Closing connection.")
                    if debug: print("User agent: Unexpected status. Closing connection.")
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT


            # -------------------------------------------------
            elif self.currentState == State.CLOSE_CONNECTIONS_AND_EXIT:
                if debug: print("User agent: close connection and exit")
                self.cleanUp()
                status, response = self.closeConnection()
                if status == Status.CONNECTION_CLOSED:
                    if debug: print("User agent: Simulation finished.")
                    return "User agent: Simulation finished."
                else:
                    self.log.info("User agent: Unexpected status. Connection closed nevertheless.")
                    if debug: print("User agent: Unexpected status. Connection closed nevertheless.")
                    return "User agent: Simulation finished with unexpected status."


            # -------------------------------------------------
            else:
                self.log.error("State not implemented.")
                return "State not implemented."
                self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT


            self.log.info("User agent: Done. Next state: %s", self.currentState)

        # No message to return.
        return None

#    def closeConnection(self):
#        """
#        Terminate connection.
#        """
#        self.locauthClient.closeMainSocket()
#        return Status.CONNECTION_CLOSED, {}


    def start(self, kwargs={}):
        """
        Starts the Location Service agent at the initial state and possibly a few default options.

        """
        # Now start the protocol.
        self.currentState = State.START_IDLE
        # Call runProtocol, but do not unpack kwargs just yet, as runProtocol takes only one argument. The argument will be unpacked when the next state handler
        # is called.
        self.runProtocol(kwargs)

    def advertiseServiceAndlistenForConnections(self):
        """
        Advertises Location Service service and listens for connection requests from user agents through a network medium.

        Returns
        -------
        IntNum, dict
            Status of processing this state.
            The response payload received from the other peer, if any.
        """
        # server = BluetoothNetService(NetServiceType.BLUETOOTH_SERVER, uuid = "1e0ca4ea-299d-4335-93eb-27fcfe7fFEFF", service = "LOCAUTH Service") # Kethor
        # server.createSocket()
        # Must be non-blocking with a timeout.
        # server.listenForConnections()
        # Must indicate whether a connection was established.
        return Status.NOT_IMPLEMENTED, {}

#    def sendMessage(self, exchangeType, messageType, payload):
#        """
#        Aids in preparing a message to send through a socket, i.e., serializing the dictionary that composes the payload
#        and sending through the connection socket.
#
#        The JSON serializer will utilize jsonhelper.KeyEncoder to serialize pairing.Element objects, if present.
#
#        The function includes a simplified length field to facilitate receiving the whole payload by the other peer with multiple socket recv calls.
#
#        Parameters
#        ----------
#        exchangeType : int
#            The type of exchange to which this message belongs.
#        messageType : bool
#            True if it is a response message, False if it is a request message.
#        payload : dict
#            Dictionary containing the payload to serialize and send.
#
#        Returns
#        -------
#        byte str
#            The raw message that will be sent through the socket. Returning the exact raw message facilitates the calculation of <SignedOctets> by the
#            protocol.
#
#        Notes
#        -----
#        See http://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data
#
#        """
#        rawMessage = locationserviceutility.sendMessage(self.spii, self.spir, exchangeType, messageType, constants.HEADER_SENDER_TYPE_INITIATOR, self.currentSendingMessageCounter, payload, self.locauthClient.sendMessageThruMainSocketBytes, self.groupObject.param)
#        self.currentSendingMessageCounter += 1
#        if debug: print("User agent simulator, send raw message:\n", rawMessage)
#        return rawMessage

#    def sendEncryptedMessage(self, exchangeType, messageType, payload):
#        """
#        Aids in preparing an encrypted message to send through a socket, i.e., serializing the dictionary that composes the payload
#        and sending through the connection socket. It uses the agent's one-way DH secret shared key for encryption.
#
#        The JSON serializer will utilize jsonhelper.KeyEncoder to serialize pairing.Element objects, if present.
#
#        Parameters
#        ----------
#        exchangeType : int
#            The type of exchange to which this message belongs.
#        messageType : bool
#            True if it is a response message, False if it is a request message.
#        payload : dict
#            Dictionary containing the payload to serialize and send.
#
#        Returns
#        -------
#        byte str
#            The raw message that will be sent through the socket. Returning the exact raw message facilitates the calculation of <SignedOctets> by the
#            protocol.
#
#        Notes
#        -----
#        See http://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data
#
#        """
#        # The user agent is the initator.
#        rawMessage = locationserviceutility.sendEncryptedMessage(self.spii, self.spir, exchangeType, messageType, constants.HEADER_SENDER_TYPE_INITIATOR, self.currentSendingMessageCounter, payload, self.locauthClient.sendMessageThruMainSocketBytes, self.groupObject.param, self.skei)
#        self.currentSendingMessageCounter += 1
#        if debug: print("Location Service simulator, send encrypted raw message:\n", rawMessage)
#        return rawMessage

#    def receiveMessage(self, exchangeType, messageType, enforceSpiCheck=True):
#        """
#        Receives a message from the socket and deserializes it before returning it. It also validates the header and returns True if the header is OK, False otherwise.
#        The message is always returned regardless of the validity of the header.
#
#
#        Parameters
#        ----------
#        exchangeType : int
#            The type of exchange to which this message belongs.
#        messageType : bool
#            True if it is a response message, False if it is a request message.
#        enforceSpiCheck : bool, optional
#            If True, the header SPI values will be checked against the expected ones. If False, check will not be made.
#            The purpose is to allow an agent to actually receive yet unknown SPI values from the other peer and set them locally, and then enforce checking for
#            subsequent messages.
#
#        Returns
#        -------
#        dict, bool
#            dict: Deserialized message received from the socket.
#            bool: True if header is valid, i.e., all values are those expected. False otherwise.
#
#        Notes
#        -----
#        See http://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data
#        """
#        self.expectedReceivedMessageCounter += 1
#        message = locationserviceutility.receiveMessage(self.locauthClient.receiveMessageFromMainSocketBytes)
#        if debug: print("User agent: message received:\n", message)
#        isHeaderValid = self.validateMessageHeader(message[constants.HEADER_FIELD_NAME], exchangeType, messageType, enforceSpiCheck=enforceSpiCheck)
#        if debug: print("User agent: receiveMessage:\nmessage:\n", message, "\nHeader: ", isHeaderValid)
#        return message, isHeaderValid

#    def receiveEncryptedMessage(self, exchangeType, messageType, enforceSpiCheck=True):
#        """
#        Receives an encrypted message from the socket and deserializes it before returning it. It also validates the header and returns True if the header is OK, False otherwise.
#        The message is always returned regardless of the validity of the header.
#        The function uses the one-way DH shared key to decrypt the message from the other peer.
#
#        Parameters
#        ----------
#        exchangeType : int
#            The type of exchange to which this message belongs.
#        messageType : bool
#            True if it is a response message, False if it is a request message.
#        enforceSpiCheck : bool, optional
#            If True, the header SPI values will be checked against the expected ones. If False, check will not be made.
#            The purpose is to allow an agent to actually receive yet unknown SPI values from the other peer and set them locally, and then enforce checking for
#            subsequent messages.
#
#        Returns
#        -------
#        dict, bool
#            dict: Deserialized message received from the socket.
#            bool: True if header is valid, i.e., all values are those expected. False otherwise.
#
#        Notes
#        -----
#        See http://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data
#        """
#        self.expectedReceivedMessageCounter += 1
#        # The user agent is the initiator. Must user responder key.
#        message = locationserviceutility.receiveEncryptedMessage(self.locauthClient.receiveMessageFromMainSocketBytes, self.sker)
#        if debug: print("User agent: encrypted message received:\n", message)
#        isHeaderValid = self.validateMessageHeader(message[constants.HEADER_FIELD_NAME], exchangeType, messageType, enforceSpiCheck=enforceSpiCheck)
#        if debug: print("User agent: receiveEncryptedMessage:\nmessage:\n", message, "\nHeader: ", isHeaderValid)
#        return message, isHeaderValid

#    def validateMessageHeader(self, header, exchangeType, messageType, enforceSpiCheck=True):
#        """
#        Validates the header of a received message, i.e., checks whether SPI values match, the expected message counter is correct, whether the exchangeType is the one expected,
#        the messageType is the one expected, the message sender is the initiator.
#
#        This is not an inner, sub-level dictionary, but an outer, first level dictionary, i.e., [header_field] : value, [header_field]: value, etc.
#
#        Parameters
#        ----------
#        header : dict
#            The header to be verified in dict format.
#            This is not an inner, sub-level dictionary, but an outer, first level dictionary, i.e., [header_field] : value, [header_field]: value, etc.
#        exchangeType : int
#            The type of exchange to which this message belongs.
#        messageType : bool
#            True if it is a response message, False if it is a request message.
#        enforceSpiCheck : bool, optional
#            If True, the header SPI values will be checked against the expected ones. If False, check will not be made.
#            The purpose is to allow an agent to actually receive yet unknown SPI values from the other peer and set them locally, and then enforce checking for
#            subsequent messages.
#
#        Returns
#        -------
#        bool
#            True if header is valid, i.e., all values are those expected.
#            False otherwise.
#        """
#        return locationserviceutility.validateMessageHeader(self, header, exchangeType, messageType, enforceSpiCheck=enforceSpiCheck)

    def __processStartIdle(self, message):
        """
        Process the START_IDLE state.

        message: message to process. In reality, nothing.

        Return:
        Response payload. None, actually.
        """

        # Do the things from this state.
        # Nothing to do here but go to the next state.
        # Generate a response, if needed, to be sent to the other party.
        response = None
        return response


    def findAndConnectToLocationService(self):
        """
        Finds a service advertisement from Location Service and connects to it (if found).
        """
#        serviceMatches = bluetooth.find_service(uuid = "1e0ca4ea-299d-4335-93eb-27fcfe7fFEFF")
#        if len(serviceMatches) == 0:
#            print("No services found.")
#            sys.exit(0)
#        for serviceMatchesIterator in serviceMatches:
#            print(serviceMatchesIterator)
#
#        firstMatch = serviceMatches[0]
#        port = firstMatch["port"]
#        name = firstMatch["name"]
#        host = firstMatch["host"]
#
#        print("Connecting to ", name, " on ", host)
#
#        client = BluetoothNetService(NetServiceType.BLUETOOTH_CLIENT, destAddress = host, destPort = port) #Terminus
#        client.createSocket()
#
#        client.connectToDestination()
        pass

    def sendPayloadToLocationService(self, payload):
        """
        Sends a payload to Location Service agent through a network medium.

        Parameters
        ----------
        payload : byte str
            payload, as byte str, to send to Location Service agent.
        """
        # client.sendMessageThruMainSocket(payload)
        pass

    def receivePayloadFromLocationService(self):
        """
        Receives a payload, as byte str, from the Location Service agent through a network medium.

        Returns
        -------
        byte str
            payload received from the Location Service.
        """
        # payload = client.receiveMessageFromMainSocket()
        return ""

    def closeConnectionToLocationService(self):
        """
        Closes the connection to the Location Service agent.
        """
        # client.closeMainSocket()
        pass

#    def cleanUp(self):
#        """
#        Stop timers, etc., before leaving the simulation.
#        """
#        pass

#    def computeAuthTier1i(self):
#        """
#        Computes the AUTH_TIER1i value, together with the auxiliary values (such as <SignedOctets>).
#
#        Returns
#        -------
#        byte str
#            AUTH_TIER1i value.
#        """
#        # AUTH_TIER1_i = prf(prf+(Ni | Nr, “LocAuth Tier_1” | Nb), <SignedOctets_i> | KEr).
#        # signed_octets = bytes(self.packets[0]) + self.Nr + prf(self.SK_pi, id_payload._data)
#        signedOctets = locationserviceutility.computeSignedOctets(self.messageContainer[constants.SIGNED_OCTETS_KEI_NI_RAW_MESSAGE], self.nr, self.messageContainer[constants.SIGNED_OCTETS_IDI_PAYLOAD_TIER1], self.skpi)
#        # Before computing AUTH value, certain values must be converted to appropriate byte str, such as KEx values that are (x,y) points.
#        authTier1i = locationserviceutility.computeAuthTier1(signedOctets, self.ni, self.nr, self.currentNb, self.ker)
#        return authTier1i

#    def computeAuthTier1r(self):
#        """
#        Computes the AUTH_TIER1r value, together with the auxiliary values (such as <SignedOctets>).
#
#        Returns
#        -------
#        byte str
#            AUTH_TIER1r value.
#        """
#        # AUTH_TIER1_r=prf(prf+(Ni | Nr, “LocAuth Tier_1” | Nb), <SignedOctets_r> | KEi).
#        # signed_octets = bytes(self.packets[0]) + self.Ni + prf(self.SK_pr, id_payload._data)
#        signedOctets = locationserviceutility.computeSignedOctets(self.messageContainer[constants.SIGNED_OCTETS_KER_NR_RAW_MESSAGE], self.ni, self.messageContainer[constants.SIGNED_OCTETS_IDR_PAYLOAD], self.skpr)
#        # Before computing AUTH value, certain values must be converted to appropriate byte str, such as KEx values that are (x,y) points.
#        authTier1r = locationserviceutility.computeAuthTier1(signedOctets, self.ni, self.nr, self.currentNb, self.kei)
#        return authTier1r
