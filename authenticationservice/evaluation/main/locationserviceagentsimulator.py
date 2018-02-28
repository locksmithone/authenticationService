# -*- coding: utf-8 -*-
"""
Created on Thu May  5 11:02:08 2016

@author: locksmith
"""

from states import State
#import logging
#import time
#import json
#import jsonhelper
import constants
#import locationservice
#from netservice import NetService
#import netservice
#import netservicetype
from status import Status
import Crypto.Random.random
import Crypto.Hash.SHA256
import locationserviceutility
#from charm.core.math.pairing import hashPair as hashPairSha256
#import threading
import agentsimulator
import json
import jsonhelper
import hashlib

# Set this variable to True to print debugging messages.
debug = True

class LocationServiceAgentSimulator(agentsimulator.AgentSimulator):
    """
    This class simulates an Agent running the Location Service (Loc-Auth) and interacting with another agent,
    typically a user agent or a Relying-Party (RP)/Authority.

    This agent simulator is implemented as a Finite-State Machine to run the LOCATHE protocol. The states are
    defined in module states.py.
    """

#    def __init__(self, locationServiceObject):
#        """
#        Initialize the object.
#
#        locationServiceObject: Location Service agent object instantiated already instantiated somewhere else.
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
#        self.locationServiceObject = locationservice.LocationService() # This line is useless; it is here just to provide code autocompletion from Spyder (to provide a type hint).
#        self.locationServiceObject = locationServiceObject
#        #self.log.info("Database filename set: %s", self.DATABASE)
#        self.log.info("Location Service Agent Simulator instantiated.")
#
#        self.hybridAbeMultiAuthorityObject, self.globalParameter, self.groupObject = self.locationServiceObject.locationServiceAuthorityObject.createHybridABEMultiAuthorityObject()
#
#        # The socket server.
#        self.locauthServer = netservice.NetService(netservicetype.NetServiceType.SERVER, 'localhost')
#        # The agent type, such that some functions can make decisions based on this type.
#        self.agentType = constants.LOCATHE_LOCATION_SERVICE_AGENT_TYPE
#
#        # Resets or initialize variables.
#        self.resetInstanceVariables()
#        # Setup BNONCE scheduler.
#        #self.bnonceScheduler = sched.scheduler(time.time, time.sleep)
#        # Setup BNONCE threading timer.
#        self.bnonceTimer = threading.Timer(0, self.scheduleBnonceUpdate)

    def resetInstanceVariables(self):
        """
        Resets or reinitializes instance variables for a clean LOCATHE session.
        """
        # Call superclass method.
        super().resetInstanceVariables()
        # Set child class instance variables.
        self.userEntityID = constants.ENTITY_ID_TIER1_ANONYMOUS_USER

    def processStartIdle(self, bnonceAccessPolicy='global.locathe', bnonceLengthBits=constants.BNONCE_LENGTH_BITS, bnonceAuthorityList=[constants.ENTITY_ID_LOCATION_SERVICE]):
        """
        START_IDLE state sets a few parameters coming from the start() function, and then should pass control to the next state (Broadcast).

        Parameters
        ----------
        bnonceAccessPolicy : str
            The acess policy, a logic expression, for the ABE encryption of BNONCE.
        bnonceLengthBits : int
            The length, in bits, for the BNONCE plaintext (not the length of the ciphertext).
        bnonceAuthorityList : list of str
            A list of entityIDs of authorities whose ABE public keys will be utilized to encrypt the BNONCE plaintext.

        Returns
        -------
        IntNum, dict
            Status of processing this state.
            The response payload received from the other peer, if any.
        """
        if debug: print("Location Server: processStartIdle.")
        if debug: print("Location Server: processStartIdle. Reset instance variables.")
        # Reset states.
        self.resetInstanceVariables()

        self.bnonceAccessPolicy = bnonceAccessPolicy
        self.bnonceAuthorityList = bnonceAuthorityList
        self.bnonceLengthBits = bnonceLengthBits # In bits.
        # Initiate BNONCE scheduler.
        #self.scheduleBnonceUpdate()
        # Initiate BNONCE timer.
        self.bnonceTimer.start()

        return Status.START_PROTOCOL, {}

    def processBroadcastEcdheAdvertisementBluetoothLocauthAdvertisement(self):
        """
        Process the BROADCAST_ECDHE_ADVERTISEMENT_BLUETOOTH_LOCAUTH_ADVERTISEMENT state.

        Advertise Loc-Auth Bluetooth service.
        Listen to Bluetooth connection requests, and wait.

        If there is a request received and timer is not expired (?), trigger next state.
        If timer expires (timeout), restart state.


        message: message to process. Could be nonce to broadcast and the access policy...

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
        # For the purposes of this simulation using INET, this state does not really do anything useful. Just send a mock payload with Bluetooth advertisement
        # data and return a typical Bluetooth status.
        if debug: print("Location Server: processBroadcastEcdheAdvertisementBluetoothLocauthAdvertisement.")
        advertisementPayload = {constants.PAYLOAD_FIELD_NAME_UUID:constants.LOCAUTH_UUID, constants.PAYLOAD_FIELD_NAME_SERVICE_DESCRIPTION: constants.LOCAUTH_BLUETOOTH_SERVICE_DESCRIPTION}
        # Header info. The very first message has, as SPIr, a random value, and SPIi has zero as it is yet unknown.
        self.spir = locationserviceutility.generateSpiRandomValue(constants.SPI_LENGTH_BYTES)
        self.spii = b'\x00'
        if debug: print("Location Server: about to send message at processBroadcastEcdheAdvertisementBluetoothLocauthAdvertisement.")
        message = self.sendMessage(constants.HEADER_EXCHANGE_TYPE_BROADCAST_ECDHE_BLUETOOTH_ADVERTISEMENT, constants.HEADER_MESSAGE_TYPE_REQUEST, advertisementPayload)
        # Save the raw payload as an IDr payload for later <SignedOctets> computation. Strip the header from the raw message above.
        self.messageContainer.update({constants.SIGNED_OCTETS_IDR_PAYLOAD: locationserviceutility.extractPayloadFromRawMessage(message)})
        #self.serializeAndSendPayload(advertisementPayload)
        # Maintain the same status, as this state should in fact return this status when in Bluetooth mode.
        return Status.SERVICE_ADVERTISEMENT_SENT, {}

    def processBroadcastEcdheBroadcastBnonce(self):
        """
        Process the State.BROADCAST_ECDHE_BROADCAST_BNONCE state.

        Summary:
        Check Nb nonce validity timer.
        If timeout, then Initiate Nb nonce validity timer.
            Pick random nonce Nb.
            BNONCE = ABE(AccessPolicy, Nb)
            Sign BNONCE.

        Wait for KEi, Ni from user agent/initiator.

        Returns
        -------
        IntNum, dict
            Status of processing this state.
            The response payload received from the other peer, if any.
        """
        if debug: print("Location Server: Broadcast BNONCE.")
        # Will wait here if nb is empty, until it is not. Sometimes the updateBnonce function takes too long, or hangs there forever, and the
        # BNONCE is not updated before this function executes. Let's wait here to see what happens.
        while self.currentNb == b'':
            self.log.info("BNONCE values still empty. Waiting to broadcast...")
            if debug: print("Location Server: Broadcast BNONCE: BNONCE empty. Waiting...")
        # Prepare the payload.
        if debug: print("Location Server: sending BNONCE...")
        bnoncePayload = {constants.PAYLOAD_FIELD_NAME_BNONCE:self.currentBnonceSerialized,
                         constants.PAYLOAD_FIELD_NAME_BNONCE_SIGNATURE:self.currentBnonceSignature,
                         constants.PAYLOAD_FIELD_NAME_LOCATION_SERVICE_CERTIFICATE:self.agentObject.getCertificateAsString()}

        self.sendMessage(constants.HEADER_EXCHANGE_TYPE_BROADCAST_ECDHE_BROADCAST_BNONCE, constants.HEADER_MESSAGE_TYPE_REQUEST, bnoncePayload)
        # -------------- Receive KEi, Ni --------------
        # Now wait for KEi, Ni.
        if debug: print("Location Server: waiting for KEi, Ni.")
        # Cannot enforce SPI check. KEi, Ni is the first message from the user agent, and thus Location Service does not know SPIi.
        response, isHeaderValid = self.receiveMessage(constants.HEADER_EXCHANGE_TYPE_SEND_KE_K, constants.HEADER_MESSAGE_TYPE_RESPONSE, enforceSpiCheck=False)
        # Validate header.
        if not isHeaderValid:
            # Unexpected values within the message header. Leave.
            return Status.INVALID_HEADER, response
        # Header is valid. Proceed.
        # Check whether KEi and Ni are in the payload.
        if (constants.PAYLOAD_FIELD_NAME_KEI in response) and (constants.PAYLOAD_FIELD_NAME_NI in response):
            if debug: print("Location Server: received KEi, Ni.")
            self.kei = response[constants.PAYLOAD_FIELD_NAME_KEI]
            self.ni = response[constants.PAYLOAD_FIELD_NAME_NI]
            self.spii = response[constants.HEADER_FIELD_NAME][constants.HEADER_FIELD_NAME_SPI_I]
            # Save the raw message for computing <SignedOctets> later.
            self.messageContainer.update({constants.SIGNED_OCTETS_KEI_NI_RAW_MESSAGE: response[constants.PAYLOAD_FIELD_NAME_RAW_MESSAGE]})
            return Status.KEI_NI_RECEIVED, response
        else:
            return Status.INVALID_KEI_NI, response

    def processListenForConnections(self, timeout=None):
        """
        Process the State.LISTEN_FOR_CONNECTIONS state. This is a helper state that allows this simulator to listen and accept connections before
        entering the advertisement and broadcast states, as TCP/IP is being used instead of Bluetooth stack (and therefore we need to connect before
        sending anything).

        Parameters
        ----------
        timeout : int
            If timeout > 0, this specifies the maximum wait time, in seconds, for a connection request to be heard.
            If timeout is None, the function will block until a connection request is received.

        Returns
        -------
        IntNum, dict
            Status of processing this state.
            The response payload received from the other peer, if any.
        """
        if debug: print("Location Server: processListenForConnections.")
        self.socketServer.createSocket()
        #self.locauthServer.createSocket()
        self.log.info("Location Server: socket created. Start listening on port: %s", self.socketServer.srcPort)
        socket_, address = self.socketServer.listenForConnections(timeout=timeout)
        if socket_ is not None:
            # A connection request was accepted. Proceed to Broadcast phase and send BNONCE immediately.
            if debug: print("Location Server: connection request received and accepted.")
            status = Status.CONNECTION_REQUEST_ACCEPTED_CONNECTED
            responsePayload = {}
        else:
            if debug: print("Location Server: listen for connections timed out.")
            status = Status.TIMEOUT
            responsePayload = {}
        return status, responsePayload

    def processBroadcastEcdheSendKerNr(self):
        """
        Process the State.BROADCAST_ECDHE_SEND_KEr_Nr state.

        Here, the Server picks a random value kr and calculates (in ellyptic curve mode) KEr = kr * G, where G is the group generator. It also picks a random
        value Nr, and sends both Nr ad KEr to the user agent.
        """
        if debug: print("Location Server: sending KEr, Nr.")
        self.ker, self.kr, self.nr = locationserviceutility.computeKexAndNx()
        # Send message with ker, kr, nr payload (header will be automatically computed), and save it for later <SignedOctets> computation.
        message = self.sendMessage(constants.HEADER_EXCHANGE_TYPE_SEND_KE_K, constants.HEADER_MESSAGE_TYPE_REQUEST, {constants.PAYLOAD_FIELD_NAME_KER:self.ker, constants.PAYLOAD_FIELD_NAME_NR:self.nr})
        self.messageContainer.update({constants.SIGNED_OCTETS_KER_NR_RAW_MESSAGE: message})
        # Now calculate the final part of ECDHE, i.e., the shared secrets.
        if debug: print("Location Server: proceeding to compute shared secrets.")
        self.computeEcdheSecrets()
        # Done with Broadcast phase.
        return Status.SHARED_SECRETS_COMPUTED, {}

    def processTier1PrivacyAuthentication(self):
        """
        Do Tier_1_Privacy_Authentication.
        """
        if debug: print("Location Server: processTier1PrivacyAuthentication.")
        if debug: print("Current messageContainer:\n", self.messageContainer)
        # First, receive the AUTH_TIER1_i from the user agent (initiator).
        response, isHeaderValid = self.receiveEncryptedMessage(constants.HEADER_EXCHANGE_TYPE_AUTH1, constants.HEADER_MESSAGE_TYPE_RESPONSE)
        # Validate header.
        if not isHeaderValid:
            # Unexpected values within the message header. Leave.
            return Status.INVALID_HEADER, response
        # Header is valid. Verify whether AUTH_TIER1_i is valid by computing it here and comparing the hashes of each.
        # At this tier, the IDi is anonymous. Add it here to messageContainer.
        self.messageContainer.update({constants.SIGNED_OCTETS_IDI_PAYLOAD_TIER1:locationserviceutility.buildAnonymousIdPayload()})
        authTier1iLocal = self.computeAuthTier1i()
        if debug: print("Location Server: authTier1i: ", authTier1iLocal, "\nLength: ", len(authTier1iLocal))
        # Fetch the AUTH_TIER1_i value from the user agent message.
        authTier1iReceived = response[constants.PAYLOAD_FIELD_NAME_AUTH_TIER1_I]
        if debug: print("Location Server: authTier1iLocal type: ", type(authTier1iLocal), authTier1iLocal)
        if debug: print("Location Server: authTier1iReceived type: ", type(authTier1iReceived), authTier1iReceived)
        # Compare the values and log error if their hashes differ. Use hashes to illustrate timing attack mitigation.
        if hashlib.sha256(authTier1iLocal).digest() != hashlib.sha256(authTier1iReceived).digest():
            if debug: print("Location Server: AUTH_TIER1 values differ.")
            self.log.error("AUTH_TIER1 values do not match.")
            return Status.INVALID_TIER1_PAYLOAD, response
        # Values match. Prepare the AUTH_TIER1_r payload and the AUTH signature.
        # In the SignedOctets of Location Service (responder), the IDr payload contains the Bluetooth advertisement values as IDr.
        # The IDr, of course, can be any appropriate ID value for the Location Service agent. The signature, both for the BNONCE and for the
        # AUTHTier1r payload, confirms that a known Location Service is computing and signing the values (and not necessarily the same
        # device that advertised the Bluetooth advertisement payload).
        authTier1r = self.computeAuthTier1r()
        authTier1rSignature = self.agentObject.sign(authTier1r)
        idrValue = json.loads(self.messageContainer[constants.SIGNED_OCTETS_IDR_PAYLOAD].decode(), cls=jsonhelper.KeyDecoder)
        # Send the encrypted message with the AUTH payload.
        message = self.sendEncryptedMessage(constants.HEADER_EXCHANGE_TYPE_AUTH1, constants.HEADER_MESSAGE_TYPE_REQUEST,
                                            {constants.PAYLOAD_FIELD_NAME_AUTH_TIER1_R: authTier1r,
                                             constants.PAYLOAD_FIELD_NAME_ID_R: idrValue,
                                             constants.PAYLOAD_FIELD_NAME_AUTH_TIER1_R_SIGNATURE: authTier1rSignature,
                                             constants.PAYLOAD_FIELD_NAME_LOCATION_SERVICE_CERTIFICATE: self.agentObject.getCertificateAsString()})
        if debug: print("Location Server: AUTH_TIER1r sent:\n", message)
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
        Update sAuth.
        SK_er(currentFactorScore, minimumScore)

        Final round:
        Initiator sends to Responder:
        SK_ei(LPKi)

        Responder sends to Initiator:
        SK_er(LPKr)

        Proceed to Exchange Authentication/LTK Generation.

        Notes
        -----
        The function returns the response message sent by the user agent, from which the caller can extract the userID and pass it to the next
        state (AdditionalAuthenticationFactors gathering) if needed.
        """
        # ---------- First Round ----------
        # Initiator sends to Responder:
        # SK_ei(ENONCE, keyType, Idi, AUTH_TIER2_i)
        # Responder sends to Initiator:
        # SE_er(Idr, AUTH_TIER2_r, sign(AUTH_TIER2_r), currentFactorScore, minimumScore)
        # Receive message from initiator/user agent, containing the first ENONCE, its related keyType, IDi, AUTH_TIER2_i.
        response, isHeaderValid = self.receiveEncryptedMessage(constants.HEADER_EXCHANGE_TYPE_AUTH2, constants.HEADER_MESSAGE_TYPE_RESPONSE)
        if not isHeaderValid:
            # Unexpected values within the message header. Leave.
            self.log.error("Invalid header.")
            return Status.INVALID_HEADER, response
        # Let's do some assertions here before proceeding.
        # There has to be a IDi payload, there has to be a keyType payload, and the entityID specified in the IDi payload must exist.
        # Finally, the ENONCE must be there. Otherwise, no point in continuing.
        if constants.PAYLOAD_FIELD_NAME_ID_I not in response or constants.PAYLOAD_FIELD_NAME_AUTHENTICATION_KEY_TYPE not in response or \
        not locationserviceutility.isEntityIDvalid(response[constants.PAYLOAD_FIELD_NAME_ID_I], database=self.agentObject.database) or constants.PAYLOAD_FIELD_NAME_ENONCE not in response:
            self.log.error("Missing necessary info in message (IDi, keyType, IDi not existent, ENONCE).")
            return Status.INVALID_TIER2_PAYLOAD, response

        # Fetch the userID (IDi) payload and put it into the messageContainer, such that we simulate this operation from an independent IDi payload.
        # Since the response containts the dictionary, and not raw bytes, we must fetch the IDi and simulate a raw bytes IDi payload, hence the
        # constructIDiPayload() function.
        # What we are not testing here is whether the IDi is the same IDr, i.e., whether the initiator is the same Location Service, in a
        # possible reflection attack.
        # TODO: Perhaps we should check this here, or allow one peer to connect to itself if factors exists?
        idIpayload = self.constructIDiPayload(response)
        self.messageContainer.update({constants.SIGNED_OCTETS_IDI_PAYLOAD_TIER2: idIpayload})
        # Compute the AUTH_TIER2_i value for verification before operating with the ENONCE.
        authTier2iLocal = self.computeAuthTier2i()
        # Compare the values and log error if their hashes differ. Use hashes to illustrate timing attack mitigation.
        authTier2iReceived = response[constants.PAYLOAD_FIELD_NAME_AUTH_TIER2_I]
        if hashlib.sha256(authTier2iLocal).digest() != hashlib.sha256(authTier2iReceived).digest():
            if debug: print("Location Server: AUTH_TIER2 values differ.")
            self.log.error("AUTH_TIER2 values do not match.")
            return Status.INVALID_TIER2_PAYLOAD, response

        # Save the user entityID for further use.
        self.userEntityID = response[constants.PAYLOAD_FIELD_NAME_ID_I]
        # From the userID (IDi payload), fetch the user key corresponding to the keyType transmitted by the user, such that we can construct Spwd and Kpwd.
        # I believe the database will not have Spwd (stored) passwords, since PBKDF2 is a better scheme to transform the passwords anyway.
        # Let's keep the Spwd within the transitory LOCATHE transformation for now, or possibly eliminate this step altogether and go straight to Kpwd.
        userKeyList = locationserviceutility.getEntityKeysOfType(self.userEntityID, response[constants.PAYLOAD_FIELD_NAME_AUTHENTICATION_KEY_TYPE],
                                                                 database=self.agentObject.database)
        # Return immediately if no user key for the entityID was found.
        if not userKeyList:
            return Status.USER_KEY_NOT_FOUND, response

        # Let's use the first key in the list, which is the key that will expire the soonest. Convert it to bytes if not already into bytes form.
        userKey = userKeyList[0] if not hasattr(userKeyList[0], 'encode') else userKeyList[0].encode()
        # Compute Kpwd such that we can decrypt ENONCE. We cannot authenticate the decryption, however. We must comnpute the LSK/LPK pair
        # and verify values in the next step of LOCATHE.
        self.decryptEnonceUpdateSauthAndCurrentFactorScore(userKey, response)
#        kpwd = self.computeSpwdThenKpwd(userKey)
#        # Decrypt ENONCE and fetch sNonce. sNonce is a byte str.
#        sNonce = self.decryptEnonce(response[constants.PAYLOAD_FIELD_NAME_ENONCE], kpwd)
#        # Given this first ENONCE, update sAuth and prepare the message back to the initiator/user agent with the AUTH_TIER2_r, currentFactorScore and minimumFactorScore.
#        self.updateSauth(sNonce)
#        # Update current factor score.
#        self.currentFactorScore += locationserviceutility.getKeyTypeFactorScore(response[constants.PAYLOAD_FIELD_NAME_AUTHENTICATION_KEY_TYPE],
#                                                                                database=self.agentObject.database)
        # Responder sends to Initiator:
        # SE_er(Idr, AUTH_TIER2_r, sign(AUTH_TIER2_r), currentFactorScore, minimumScore)
        authTier2r = self.computeAuthTier2r()
        authTier2rSignature = self.agentObject.sign(authTier2r)
        idrValue = json.loads(self.messageContainer[constants.SIGNED_OCTETS_IDR_PAYLOAD].decode(), cls=jsonhelper.KeyDecoder)
        message = self.sendEncryptedMessage(constants.HEADER_EXCHANGE_TYPE_AUTH2, constants.HEADER_MESSAGE_TYPE_REQUEST,
                                            {constants.PAYLOAD_FIELD_NAME_AUTH_TIER2_R: authTier2r,
                                             constants.PAYLOAD_FIELD_NAME_ID_R: idrValue,
                                             constants.PAYLOAD_FIELD_NAME_AUTH_TIER2_R_SIGNATURE: authTier2rSignature,
                                             constants.PAYLOAD_FIELD_NAME_LOCATION_SERVICE_CERTIFICATE: self.agentObject.getCertificateAsString(),
                                             constants.PAYLOAD_FIELD_NAME_CURRENT_FACTOR_SCORE: self.currentFactorScore,
                                             constants.PAYLOAD_FIELD_NAME_MINIMUM_FACTOR_SCORE: self.mininumFactorScore})

        # ---------- Repeating sAuth-computing Round ----------
        # Here, go to State.TIER2_PRIVACY_AUTHENTICATION_ADDITIONAL_AUTHENTICATION_FACTORS and let it handle the gathering of factors if needed.
        # If the minimumFactorScore has already been reached, then proceed immediately to LPK/LSK state, wherein the Location Service will await
        # for a LPKi from the user agent.
        if self.currentFactorScore >= self.mininumFactorScore:
            return Status.MINIMUM_FACTOR_SCORE_FULFILLED, response
        else:
            return Status.ADDITIONAL_AUTHENTICATION_FACTORS_NEEDED, response

    def processTier2PrivacyAuthenticationAdditionalAuthenticationFactors(self):
        """
        In this state, gather additional authentication factors the user agent sends until Minimum Factor score is reached or
        surpassed, or a potential maximum number of invalid messages was received.

        When the minimum factor score is reached, proceed to the next state, typically in which LPK/LSK keys are computed and the public part, exchanged.
        """
        # ---------- Repeating sAuth-computing Round ----------
        # What we can do here is respond to ENONCE messages from the user agent until minimumFactorScore has been reached, then just expect
        # a LSK/LPK message and reject any additional ENONCE ones.
        # Likewise, if minimumFactorScore has not yet been reached, reject/disregard LSK/LPK messages. Eventually, through a timer/timeout mechanism,
        # signal a protocol error and close the connection.
        # Initiator sends to Responder: (repeat until currentFactorScore => minimumScore)
        # SK_ei(ENONCE, keyType)
        response, isHeaderValid = self.receiveEncryptedMessage(constants.HEADER_EXCHANGE_TYPE_AUTH2, constants.HEADER_MESSAGE_TYPE_RESPONSE)
        if not isHeaderValid:
            # Unexpected values within the message header. Leave.
            self.log.error("Invalid header.")
            return Status.INVALID_HEADER, response
        # Assert certain information is here.
        if constants.PAYLOAD_FIELD_NAME_AUTHENTICATION_KEY_TYPE not in response or constants.PAYLOAD_FIELD_NAME_ENONCE not in response:
            self.log.error("Missing necessary info in message (keyType, ENONCE).")
            return Status.INVALID_TIER2_PAYLOAD, response

        # CRITICAL!
        # # TODO: in this implementation, a user can maliciously present the same secret key multiple times, and effectively the Location Service
        # will accept this and increase the factor score each time the same key is presented. We must introduce here a mechanism to
        # detect whether the same factor was presented before and reject it.
        # CRITICAL!
        
        # Fetch the ENONCE, extract sNonce, update sAuth and verify whether mininumFactorScore has been reached.
        # From the userID (IDi payload), fetch the user key corresponding to the keyType transmitted by the user, such that we can construct Spwd and Kpwd.
        # I believe the database will not have Spwd (stored) passwords, since PBKDF2 is a better scheme to transform the passwords anyway.
        # Let's keep the Spwd within the transitory LOCATHE transformation for now, or possibly eliminate this step altogether and go straight to Kpwd.
        userKeyList = locationserviceutility.getEntityKeysOfType(self.userEntityID,
                                                             response[constants.PAYLOAD_FIELD_NAME_AUTHENTICATION_KEY_TYPE],
                                                             database=self.agentObject.database)
        # Return immediately if no user key for the entityID was found.
        if not userKeyList:
            return Status.USER_KEY_NOT_FOUND, response

        # Let's use the first key in the list, which is the key that will expire the soonest. Convert it to bytes if not already into bytes form.
        userKey = userKeyList[0] if not hasattr(userKeyList[0], 'encode') else userKeyList[0].encode()
        # Compute Kpwd such that we can decrypt ENONCE. We cannot authenticate the decryption, however. We must comnpute the LSK/LPK pair
        # and verify values in the next step of LOCATHE.
        self.decryptEnonceUpdateSauthAndCurrentFactorScore(userKey, response)
#        kpwd = self.computeSpwdThenKpwd(userKey)
#        # Decrypt ENONCE and fetch sNonce. sNonce is a byte str.
#        sNonce = self.decryptEnonce(response[constants.PAYLOAD_FIELD_NAME_ENONCE], kpwd)
#        # Given this first ENONCE, update sAuth and prepare the message back to the initiator/user agent with the AUTH_TIER2_r, currentFactorScore and minimumFactorScore.
#        self.updateSauth(sNonce)
#        # Update current factor score.
#        self.currentFactorScore += locationserviceutility.getKeyTypeFactorScore(response[constants.PAYLOAD_FIELD_NAME_AUTHENTICATION_KEY_TYPE],
#                                                                                database=self.agentObject.database)
#        # Responder sends to Initiator:
        # SK_er(currentFactorScore, minimumScore)
        message = self.sendEncryptedMessage(constants.HEADER_EXCHANGE_TYPE_AUTH2, constants.HEADER_MESSAGE_TYPE_REQUEST,
                                            {constants.PAYLOAD_FIELD_NAME_CURRENT_FACTOR_SCORE: self.currentFactorScore,
                                             constants.PAYLOAD_FIELD_NAME_MINIMUM_FACTOR_SCORE: self.mininumFactorScore})
        # If the minimumFactorScore has already been reached, then proceed immediately to LPK/LSK state, wherein the Location Service will await
        # for a LPKi from the user agent. Otherwise, we should stay in this state.
        if self.currentFactorScore >= self.mininumFactorScore:
            if debug: print("Location Service: Authenticated!")
            return Status.MINIMUM_FACTOR_SCORE_FULFILLED, response
        else:
            return Status.ADDITIONAL_AUTHENTICATION_FACTORS_NEEDED, response

    def processTier2PrivacyAuthenticationLPK_LSK(self):
        """
        Do Tier_2_Privacy_Authentication compute/send/receive LPK/LSK keys.
        """
        # ---------- Final Round ----------
        # Initiator sends to Responder:
        # SK_ei(LPKi)
        response, isHeaderValid = self.receiveEncryptedMessage(constants.HEADER_EXCHANGE_TYPE_AUTH2, constants.HEADER_MESSAGE_TYPE_RESPONSE)
        if not isHeaderValid:
            # Unexpected values within the message header. Leave.
            self.log.error("Invalid header.")
            return Status.INVALID_HEADER, response
        # Assert LPKi was received.
        if constants.PAYLOAD_FIELD_NAME_LPKI not in response:
            self.log.error("Missing necessary info in message (LPKi).")
            return Status.INVALID_TIER2_PAYLOAD, response
        # Store the LPKi value received from user agent initiator.
        self.lpki = response[constants.PAYLOAD_FIELD_NAME_LPKI]
        # Compute LSK/LPK pair and GE.
        self.computeLskLpkPairAndGe()
        # Responder sends to Initiator:
        # SK_er(LPKr)
        message = self.sendEncryptedMessage(constants.HEADER_EXCHANGE_TYPE_AUTH2, constants.HEADER_MESSAGE_TYPE_REQUEST,
                                            {constants.PAYLOAD_FIELD_NAME_LPKR: self.lpkr})
        return Status.TIER2_PHASE_OK, response

    def processExchangeAuthenticationJointFactorKeyGeneration(self):
        """
        Do final Exchange Authentication, JointFactorKey generation.
        Here, we simply:
            1. Receive AUTHi from user agent.
            2. Compute AUTHi locally and compare.
            3. If OK, compute AUTHr and send to user agent.
            4. Compute JointFactorKey.
            5. If certain, optional conditions are met, register JointFactoryKey to database.

        The conditions can be, for instance, only register JointFactorKey if no other valid key is present. If full authentication was obtained
        (no anonymous, Tier 1 authentication only).
        """
        # Receive AUTHi from user agent and do the routine tests.
        response, isHeaderValid = self.receiveEncryptedMessage(constants.HEADER_EXCHANGE_TYPE_JFK_HANDOFF, constants.HEADER_MESSAGE_TYPE_RESPONSE)
        if not isHeaderValid:
            self.log.error("Invalid header.")
            return Status.INVALID_HEADER, response
        # Assert AUTHi is in the message.
        if constants.PAYLOAD_FIELD_NAME_AUTH_I not in response:
            self.log.error("Missing necessary info in message (AUTHi)")
            return Status.INVALID_JFK_AUTH_PAYLOAD, response
        # Fetch the AUTHi value for later comparison.
        authiReceived = response[constants.PAYLOAD_FIELD_NAME_AUTH_I]
        # Compute AUTHi (for comparison), AUTHr (to send back to user), and JointFactorKey.
        authiLocal, authr, jointFactorKey = self.computeFinalAuthAndJointFactorKey(self.userEntityID)
        # Verify AUTHi.
        if hashlib.sha256(authiReceived).digest() != hashlib.sha256(authiLocal).digest():
            if debug: print("Location Server: AUTHi values differ.")
            self.log.error("AUTHi values do not match.")
            return Status.INVALID_JFK_AUTH_PAYLOAD, response
        # AUTHi matches. Send AUTHr to user agent. No need to wait further. Process the JointFactorKey (register it, or not) and end
        # the protocol (handoff).
        message = self.sendEncryptedMessage(constants.HEADER_EXCHANGE_TYPE_JFK_HANDOFF, constants.HEADER_MESSAGE_TYPE_REQUEST,
                                            {constants.PAYLOAD_FIELD_NAME_AUTH_R: authr})
        # Now register JointFactorKey for the user in the Location Service database, and done with the protocol.
        # Here we have a few options. If there is a valid JFK in the database, we may choose not to register another one.
        # Or, expire the old one, register the new.
        # Or, register the new one and allow the old one to remain valid.
        # If registration fails for some reason, signal that through the status message.
        if not self.registerJointFactorKey(self.userEntityID, jointFactorKey, expireExistingJFKs=True):
            return Status.AUTHENTICATION_OK_JFK_NOT_REGISTERED_HANDOFF, message
        else:
            return Status.AUTHENTICATION_OK_JFK_REGISTERED_HANDOFF, message


    def processAuthenticatedHandoff(self):
        """
        Process the State.AUTHENTICATED_HANDOFF state.

        In general, in this state the Location Service will sent its final AUTHr payload and then consider the user properly authenticated. Connection then
        proceeds with more data or by "handing off" to other medium.

        Currently, the user agent simulator does nothing in this state. The AUTHr has been sent previously, the AUTHi has been received
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
        if debug: print("Location Server: runProtocol.")
        response = payloadData

        while True:

            self.log.info("Processing state: %s", self.currentState)
            if debug: print("Location Server: processing state: ", self.currentState)

            # -------------------------------------------------
            if self.currentState == State.START_IDLE:
                # The payloadData is not really a payload, but initial arguments to be passed to the next state handler.
                self.processStartIdle(**response)
                # Set next state.
                self.currentState = State.LISTEN_FOR_CONNECTIONS

            # -------------------------------------------------
            elif self.currentState == State.LISTEN_FOR_CONNECTIONS:
                connectionAttempts = 0
                while connectionAttempts < 10:
                    status, payload = self.processListenForConnections(timeout=3)
                    self.log.info("State.LISTEN_FOR_CONNECTIONS: %s", status)
                    if status == Status.CONNECTION_REQUEST_ACCEPTED_CONNECTED:
                        if debug: print("Location Server: CONNECTION_REQUEST_ACCEPTED_CONNECTED.")
                        self.currentState = State.BROADCAST_ECDHE_ADVERTISEMENT_BLUETOOTH_LOCAUTH_ADVERTISEMENT
                        break
                    elif status == Status.TIMEOUT:
                        if debug: print("Location Server: TIMEOUT.")
                        connectionAttempts += 1
                        # Too many attempts. Exit.
                        if debug: print("Location Server: no connection request received. Exiting...")
                        #self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT
                        # Just remain in this state for now.
                        self.currentState = State.LISTEN_FOR_CONNECTIONS
                    else:
                        raise SystemExit("Unknown status found while processing State.LISTEN_FOR_CONNECTIONS.")

            # -------------------------------------------------
            elif self.currentState == State.BROADCAST_ECDHE_ADVERTISEMENT_BLUETOOTH_LOCAUTH_ADVERTISEMENT:
                status, response = self.processBroadcastEcdheAdvertisementBluetoothLocauthAdvertisement()
                if status == Status.SERVICE_ADVERTISEMENT_SENT:
                    if debug: print("Location Server: finished Bluetooth service advertising.")
                    self.currentState = State.BROADCAST_ECDHE_BROADCAST_BNONCE
                else:
                    self.currentState = State.BROADCAST_ECDHE_ADVERTISEMENT_BLUETOOTH_LOCAUTH_ADVERTISEMENT

            # -------------------------------------------------
            elif self.currentState == State.BROADCAST_ECDHE_BROADCAST_BNONCE:
                status, response = self.processBroadcastEcdheBroadcastBnonce()
                if Status.KEI_NI_RECEIVED:
                    if debug: print("Location Server: KEI_NI_RECEIVED, variables set.")
                    # The instance variables kei and ni have been set by the function.
                    self.currentState = State.BROADCAST_ECDHE_SEND_KER_NR
                elif Status.INVALID_KEI_NI:
                    if debug: print("Location Server: invalid KEI_NI.")
                    #self.currentState = State.BROADCAST_ECDHE_ADVERTISEMENT_BLUETOOTH_LOCAUTH_ADVERTISEMENT
                    # Let's just give up and close the connection for now.
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT

                elif Status.INVALID_HEADER:
                    if debug: print("Location Server: invalid header values.")
                    #self.currentState = State.BROADCAST_ECDHE_ADVERTISEMENT_BLUETOOTH_LOCAUTH_ADVERTISEMENT
                    # Let's just give up and close the connection for now.
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT



            # -------------------------------------------------
            elif self.currentState == State.BROADCAST_ECDHE_SEND_KER_NR:
                status, response = self.processBroadcastEcdheSendKerNr()
                if status == Status.SHARED_SECRETS_COMPUTED:
                    if debug: print("Location Server: SHARED_SECRETS_COMPUTED.")
                    self.currentState = State.TIER1_PRIVACY_AUTHENTICATION
                else:
                    # TODO: What to do else? Time out and kill connection...
                    #self.currentState = State.BROADCAST_ECDHE_SEND_KER_NR
                    # Let's just give up and close the connection for now.
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT


            # -------------------------------------------------
            elif self.currentState == State.TIER1_PRIVACY_AUTHENTICATION:
                status, response = self.processTier1PrivacyAuthentication()
                if status == Status.TIER1_PHASE_OK:
                    self.currentState = State.TIER2_PRIVACY_AUTHENTICATION
                elif status == Status.INVALID_TIER1_PAYLOAD:
                    if debug: print("Location Server: INVALID_TIER1_PAYLOAD")
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT
                elif status == Status.INVALID_HEADER:
                    if debug: print("Location Server: State.TIER1_PRIVACY_AUTHENTICATION: Invalid header.")
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT
                else:
                    if debug: print("Location Server: State.TIER1_PRIVACY_AUTHENTICATION: Unknown status.")
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT

            # -------------------------------------------------
            elif self.currentState == State.TIER2_PRIVACY_AUTHENTICATION:
                status, response = self.processTier2PrivacyAuthentication()
                if status == Status.MINIMUM_FACTOR_SCORE_FULFILLED:
                    self.log.info("Location Server: Minimum factor score fulfilled. Go to LPK/LSK state.")
                    self.currentState = State.TIER2_PRIVACY_AUTHENTICATION_LPK_LSK
                elif status == Status.ADDITIONAL_AUTHENTICATION_FACTORS_NEEDED:
                    self.log.info("Location Server: Additional authentication factors needed.")
                    self.currentState = State.TIER2_PRIVACY_AUTHENTICATION_ADDITIONAL_AUTHENTICATION_FACTORS
                elif status == Status.INVALID_HEADER or status == Status.INVALID_TIER2_PAYLOAD or status == Status.USER_KEY_NOT_FOUND:
                    if debug: print("Location Server: State.TIER2_PRIVACY_AUTHENTICATION: header or payload or user key not found error.")
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT
                else:
                    if debug: print("Location Server: State.TIER2_PRIVACY_AUTHENTICATION: Unknown status.")
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT

            # -------------------------------------------------
            elif self.currentState == State.TIER2_PRIVACY_AUTHENTICATION_ADDITIONAL_AUTHENTICATION_FACTORS:
                status, response = self.processTier2PrivacyAuthenticationAdditionalAuthenticationFactors()
                if status == Status.MINIMUM_FACTOR_SCORE_FULFILLED:
                    self.log.info("Location Server: Minimum factor score fulfilled. Go to LPK/LSK state.")
                    self.currentState = State.TIER2_PRIVACY_AUTHENTICATION_LPK_LSK
                elif status == Status.ADDITIONAL_AUTHENTICATION_FACTORS_NEEDED:
                    self.log.info("Location Server: Additional authentication factors needed.")
                    self.currentState = State.TIER2_PRIVACY_AUTHENTICATION_ADDITIONAL_AUTHENTICATION_FACTORS
                elif status == Status.INVALID_HEADER or status == Status.INVALID_TIER2_PAYLOAD or status == Status.USER_KEY_NOT_FOUND:
                    if debug: print("Location Server: State.TIER2_PRIVACY_AUTHENTICATION_ADDITIONAL_AUTHENTICATION_FACTORS: header or payload or user key not found error.")
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT
                else:
                    if debug: print("Location Server: State.TIER2_PRIVACY_AUTHENTICATION_ADDITIONAL_AUTHENTICATION_FACTORS: Unknown status.")
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT

            # -------------------------------------------------
            elif self.currentState == State.TIER2_PRIVACY_AUTHENTICATION_LPK_LSK:
                status, response = self.processTier2PrivacyAuthenticationLPK_LSK()
                if status == Status.TIER2_PHASE_OK:
                    self.log.info("Location Server: TIER2 phase done.")
                    self.currentState = State.EXCHANGE_AUTHENTICATION_JOINT_FACTOR_KEY_GENERATION
                elif status == Status.INVALID_HEADER or status == Status.INVALID_TIER2_PAYLOAD:
                    if debug: print("Location Server: State.TIER2_PRIVACY_AUTHENTICATION_ADDITIONAL_AUTHENTICATION_FACTORS: header or payload error.")
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT
                else:
                    if debug: print("Location Server: State.TIER2_PRIVACY_AUTHENTICATION_ADDITIONAL_AUTHENTICATION_FACTORS: Unknown status.")
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT


            # -------------------------------------------------
            elif self.currentState == State.EXCHANGE_AUTHENTICATION_JOINT_FACTOR_KEY_GENERATION:
                status, response = self.processExchangeAuthenticationJointFactorKeyGeneration()
                if status == Status.INVALID_JFK_AUTH_PAYLOAD or status == Status.INVALID_HEADER:
                    if debug: print("Location Server: EXCHANGE_AUTHENTICATION_JOINT_FACTOR_KEY_GENERATION: Invalid header or invalid payload.")
                    self.log.info("Location Server: EXCHANGE_AUTHENTICATION_JOINT_FACTOR_KEY_GENERATION: Invalid header or invalid payload.")
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT
                elif status == Status.AUTHENTICATION_OK_JFK_NOT_REGISTERED_HANDOFF:
                    if debug: print("Location Server: EXCHANGE_AUTHENTICATION_JOINT_FACTOR_KEY_GENERATION: Authenticated, JFK *not* registered.")
                    self.log.info("Location Server: EXCHANGE_AUTHENTICATION_JOINT_FACTOR_KEY_GENERATION: Authenticated, JFK *not* registered.")
                    self.currentState = State.AUTHENTICATED_HANDOFF
                elif status == Status.AUTHENTICATION_OK_JFK_REGISTERED_HANDOFF:
                    if debug: print("Location Server: EXCHANGE_AUTHENTICATION_JOINT_FACTOR_KEY_GENERATION: Authenticated, JFK registered.")
                    self.log.info("Location Server: EXCHANGE_AUTHENTICATION_JOINT_FACTOR_KEY_GENERATION: Authenticated, JFK registered.")
                    self.currentState = State.AUTHENTICATED_HANDOFF
                else:
                    if debug: print("Location Server: EXCHANGE_AUTHENTICATION_JOINT_FACTOR_KEY_GENERATION: Unknown status.")
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT


            # -------------------------------------------------
            elif self.currentState == State.AUTHENTICATED_HANDOFF:
                status, response = self.processAuthenticatedHandoff()
                if status == Status.HANDED_OFF:
                    self.log.info("Location Server: LOCATHE authentication completed. Handing off to RP service.")
                    if debug: print("Location Server: LOCATHE authentication completed. Handing off to RP service.")
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT
                else:
                    self.log.info("Location Server: Unexpected status. Closing connection.")
                    if debug: print("Location Server: Unexpected status. Closing connection.")
                    self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT


            # -------------------------------------------------
            elif self.currentState == State.CLOSE_CONNECTIONS_AND_EXIT:
                if debug: print("Location Service: close connection and exit")
                self.cleanUp()
                status, response = self.closeConnection()
                if status == Status.CONNECTION_CLOSED:
                    if debug: print("Location Server: Simulation finished.")
                    return "Location Server: Simulation finished."
                else:
                    self.log.info("Location Server: Unexpected status. Connection closed nevertheless.")
                    if debug: print("Location Server: Unexpected status. Connection closed nevertheless.")
                    return "Location Server: Simulation finished with unexpected status."

            # -------------------------------------------------
            else:
                self.log.error("State not implemented.")
                return "State not implemented."
                self.currentState = State.CLOSE_CONNECTIONS_AND_EXIT


            self.log.info("Location Server: Done. Next state: %s", self.currentState)

        # No message to return.
        return None

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
#        rawMessage = locationserviceutility.sendMessage(self.spii, self.spir, exchangeType, messageType, constants.HEADER_SENDER_TYPE_RESPONDER, self.currentSendingMessageCounter, payload, self.locauthServer.sendMessageThruConnectionSocketBytes, self.groupObject.param)
#        self.currentSendingMessageCounter += 1
#        if debug: print("Location Service simulator, send raw message:\n", rawMessage)
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
#        # Location Service is the responder.
#        rawMessage = locationserviceutility.sendEncryptedMessage(self.spii, self.spir, exchangeType, messageType, constants.HEADER_SENDER_TYPE_RESPONDER, self.currentSendingMessageCounter, payload, self.locauthServer.sendMessageThruConnectionSocketBytes, self.groupObject.param, self.sker)
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
#        message = locationserviceutility.receiveMessage(self.locauthServer.receiveMessageFromConnectionSocketBytes)
#        isHeaderValid = self.validateMessageHeader(message[constants.HEADER_FIELD_NAME], exchangeType, messageType, enforceSpiCheck=enforceSpiCheck)
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
#        # Location Service is the responder. Use initiator key.
#        message = locationserviceutility.receiveEncryptedMessage(self.locauthServer.receiveMessageFromConnectionSocketBytes, self.skei)
#        isHeaderValid = self.validateMessageHeader(message[constants.HEADER_FIELD_NAME], exchangeType, messageType, enforceSpiCheck=enforceSpiCheck)
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

#    def closeConnection(self):
#        """
#        Terminate connection.
#        """
#        self.locauthServer.closeConnectionSocket()
#        self.locauthServer.closeMainSocket()
#        return Status.CONNECTION_CLOSED, {}

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
#        # Update current BNONCE/Nb.
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

#    def updateBnonce(self):
#        """
#        Updates the current BNONCE related instance variables (BNONCE value, BNONCE serialized, BNONCE signature), generating new values if the current
#        BNONCE values are expired per the BNONCE timer.
#
#        This function should be called every time a BNONCE variable is utilized, such that it is ensured the BNONCE is always curent and the protocol
#        operates as designed.
#
#        Returns
#        -------
#        bool
#            True if the current BNONCE values were updated per expiration of the timer.
#            False if the current BNONCE values are still valid.
#
#        Notes
#        -----
#        Is there a way to call this function periodically by an event manager. Since we cannot hide the BNONCE variables, nor deny them access by other
#        python functions, if a programmer uses the variables directly, without calling this function, the LOCATHE protocol implementation will be defective.
#        Likewise, there is no way to provide the current BNONCE values onlyl through the return of this function, because any static variable within
#        the function is still accessible from the outside.
#        """
##        # Check Nb validity timer.
##        # If expired, generate new Nb, BNONCE, and its signature, and store them for future reference.
##        if self.nbExpirationEpoch <= time.time(): # It is expired.
##            if debug: print("Location Server: BNONCE expired. Generating a new one...")
##            self.currentNb, self.currentBnonceSerialized, self.currentBnonceSignature = self.locationServiceObject.generateBnonce(self.bnonceAuthorityList, self.bnonceAccessPolicy, self.bnonceLengthBits)
##            if debug: print("Location Server: the Nb is: ", self.currentNb)
##            # Reset Nb validity timer.
##            self.nbExpirationEpoch = time.time() + self.defaultBroadcastExpirationSeconds
##            # Done. Return True since the values were updated.
##            return True
##        else:
##            # Done. Return False since the current values are still valid, nothing updated.
##            return False
#        if debug: print("Location Server: BNONCE expired. Generating a new one...")
#        self.currentNb, self.currentBnonceSerialized, self.currentBnonceSignature = self.locationServiceObject.generateBnonce(self.bnonceAuthorityList, self.bnonceAccessPolicy, self.bnonceLengthBits)
#        if debug: print("Location Server: the Nb is: ", self.currentNb)
#        # Reset Nb validity timer.
#        self.nbExpirationEpoch = time.time() + self.defaultBroadcastExpirationSeconds
#        #self.bnonceScheduler.enter(self.defaultBroadcastExpirationSeconds, 1, self.updateBnonce)

#    def scheduleBnonceUpdate(self):
#        """
#        Schedules the periodic update of BNONCE/Nb instance variables.
#
#        At every self.nbExpirationEpoch, the function updates the instance variables related to BNONCE/Nb, such that every function that utilizes
#        Nb are guaranteed to have updated values.
#        """
#        if debug: print("Location Server: entering BNONCE scheduler...")
#        self.updateBnonce()
#        #self.bnonceScheduler.enter(self.defaultBroadcastExpirationSeconds, 1, self.updateBnonce)
#        self.bnonceTimer = threading.Timer(constants.DEFAULT_BROADCAST_EXPIRATION_SECONDS, self.scheduleBnonceUpdate)
#        self.bnonceTimer.start()

#    def cleanUp(self):
#        """
#        Stop timers, etc., before leaving the simulation.
#        """
#        # Cancel timers.
#        self.bnonceTimer.cancel()
