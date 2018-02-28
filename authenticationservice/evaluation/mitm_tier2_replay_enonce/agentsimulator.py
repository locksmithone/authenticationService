# -*- coding: utf-8 -*-
"""
Created on Tue Jan 10 20:47:00 201y

@author: locksmith
"""

from states import State
import logging
import time
import json
import jsonhelper
import constants
import locationservice
#from netservice import NetService
import netservice
import netservicetype
from status import Status
import Crypto.Random.random
import Crypto.Util.number
import Crypto.Hash.SHA256
import locationserviceutility
from charm.core.math.pairing import hashPair # SHA256 in Charm Crypto v0.50
import threading
import charm.toolbox.symcrypto
import hashlib
import math


# Set this variable to True to print debugging messages.
debug = True

class AgentSimulator(object):
    """
    This class simulates a generic Agent running the LOCATHE protocol.

    This agent simulator is implemented as a Finite-State Machine to run the LOCATHE protocol. The states are
    defined in module states.py.
    """

    def __init__(self, agentObject, agentType=constants.LOCATHE_LOCATION_SERVICE_AGENT_TYPE):
        """
        Initialize the object.

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

        #self.log.info("Database filename set: %s", self.DATABASE)
        # Build the global objects and parameters for ABE encryption and general ellyptic curve calculations.
        self.hybridAbeMultiAuthorityObject, self.globalParameter, self.groupObject = locationserviceutility.createHybridABEMultiAuthorityObject()


        #self.agentObject = locationservice.LocationService() # This line is useless; it is here just to provide code autocompletion from Spyder (to provide a type hint).
        #self.userAgentObject = useragent.UserAgent(constants.ENTITY_ID_LOCATION_SERVICE) # Does nothing, it is here just to facilitate code completion in Spyder.
        self.agentObject = agentObject
        # The agent type, such that some functions can make decisions based on this type.
        self.agentType = agentType

        # The socket server and socket functions references.
        if self.agentType == constants.LOCATHE_LOCATION_SERVICE_AGENT_TYPE:
            self.socketServer = netservice.NetService(netservicetype.NetServiceType.SERVER, 'localhost')
            # Set references to socket functions.
            self.sendMessageBytesSocket = self.socketServer.sendMessageThruConnectionSocketBytes
            self.receiveMessageBytesSocket = self.socketServer.receiveMessageFromConnectionSocketBytes
            self.closeSocket = self.socketServer.closeConnectionSocket
            self.senderType = constants.HEADER_SENDER_TYPE_RESPONDER
        elif self.agentType == constants.LOCATHE_USER_AGENT_TYPE:
            self.socketServer = netservice.NetService(netservicetype.NetServiceType.CLIENT, 'localhost')
            # Set references to socket functions.
            self.sendMessageBytesSocket = self.socketServer.sendMessageThruMainSocketBytes
            self.receiveMessageBytesSocket = self.socketServer.receiveMessageFromMainSocketBytes
            self.closeSocket = self.socketServer.closeMainSocket
            self.senderType = constants.HEADER_SENDER_TYPE_INITIATOR
        else:
            raise ValueError("Invalid agentType!")

        # Resets or initialize variables.
        self.resetInstanceVariables()
        # Setup BNONCE threading timer. It will onlly work for Location Service agent.
        if self.agentType == constants.LOCATHE_LOCATION_SERVICE_AGENT_TYPE:
            self.bnonceTimer = threading.Timer(0, self.scheduleBnonceUpdate)

    def resetInstanceVariables(self):
        """
        Resets or reinitializes instance variables for a clean LOCATHE session.
        """
        Crypto.Random.atfork()
        # Instance variables to be populated by the protocol simulator.
        self.currentState = State.START_IDLE # Initial state.
        self.bnonceAccessPolicy = "" # Access policy for BNONCE generation.
        self.bnonceAuthorityList = [] # Authority list for which to fetch ABE public keys.
        self.bnonceLengthBits = constants.BNONCE_LENGTH_BITS # Length of BNONCE token (before encryption) in bits.
        # Nb validity timer.
        self.nbExpirationEpoch = time.time()
        # The current, valid BNONCE.
        self.currentNb = b''
        self.currentBnonceSerialized = b''
        self.currentBnonceSignature = b''
        self.defaultBroadcastExpirationSeconds = constants.DEFAULT_BROADCAST_EXPIRATION_SECONDS

        self.kei = None # pairing.Element
        self.ni = None
        self.ker = None # pairing.Element
        self.nr = None
        self.kr = None # Local value.
        self.ki = None # Local value at user agent. Location Service does not have access to this value!
        self.sharedSecret = None # pairing.Element
        self.ge = None # pairing.Element
        # This dict will contain the result of the cascading prf of sNonce values for each authentication factor ('value'), and the counter
        # respective to the number of iterations or cascading computings already made. 'value': byte str, 'counter': int.
        # Note that the sAuth value is NEVER TRANSMITTED to the other party! It is strictly local.
        self.sAuth = {'value': b'', 'counter':0}
        # By default, set the minimumFactorScore to the global value. In future implementations, the minimum can be adjusted per user.
        self.mininumFactorScore = constants.GLOBAL_MINIMUM_FACTOR_SCORE
        # The current computed factor score obtained from the authentication factors presented by the initiator.
        self.currentFactorScore = 0
        # Secret shared keys computed at Tier 2 Authentication.
        self.lski = None # Secret.
        self.lpki = None # Public. pairing.Element.
        self.lskr = None # Secret.
        self.lpkr = None # Public. pairing.Element.
        # Secret session keys.
        self.skai = None
        self.skar = None
        self.skei = None
        self.sker = None
        self.skpi = None
        self.skpr = None
        self.sksauth = None # Secret key for the sAuth prf.
        self.sktoken = None # For the prf that computes TokenAuthenticatorInteger.

        # Message storage for assisting in computing <SignedOctets>.
        self.messageContainer = {}

        # Security Parameter Index
        self.spii = b'\x00' # From initiator or user agent.
        self.spir = b'\x00' # Local, or from Location Service or responder.

        # Message counters.
        self.currentSendingMessageCounter = 0 # From Location Service or responder.
        self.expectedReceivedMessageCounter = -1 # From user agent or initiator. We start at -1, because this value will be incremented after a message is received AND before the message is validated.

    def processStartIdle(self):
        """
        START_IDLE state sets a few parameters coming from the start() function, and then should pass control to the next state (Broadcast).

        Returns
        -------
        IntNum, dict
            Status of processing this state.
            The response payload received from the other peer, if any.
        """
        return Status.START_PROTOCOL, {}

    def processBroadcastEcdheAdvertisementBluetoothLocauthAdvertisement(self):
        """
        Process the BROADCAST_ECDHE_ADVERTISEMENT_BLUETOOTH_LOCAUTH_ADVERTISEMENT state.

        Returns
        -------
        IntNum, dict
            Status of processing this state.
            The response payload received from the other peer, if any.

        """
        return Status.NOT_IMPLEMENTED, {}

    def processBroadcastEcdheBroadcastBnonce(self):
        """
        Process the State.BROADCAST_ECDHE_BROADCAST_BNONCE state.

        Notice that the BNONCE values might not have already been set by the updateBnonce function, since the updateBnonce function is executed
        within a separate thread. To avoid empty BNONCE values, this function should check whether the BNONCE variables have valid values,
        otherwise it should wait until the values are available to proceed broadcasting BNONCE.

        Returns
        -------
        IntNum, dict
            Status of processing this state.
            The response payload received from the other peer, if any.
        """
        return Status.NOT_IMPLEMENTED, {}

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
        return Status.NOT_IMPLEMENTED, {}

    def computeEcdheSecrets(self):
        """
        Compute the ECDHE secrets, such as shared secret session keys according to the ellyptic-curve Diffie-Hellman key exchange algorithm.

        Common:
        SharedSecret = ki * kr * G = ki * KEr = kr * KEi
        KeySeed = prf(Ni | Nr, SharedSecret)
        {SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr | SK_sauth | SK_token | ...} = prf+(KeySeed, Ni | Nr | SPIi | SPIr)
        """
        if debug: print(self.agentType, ": computeEcdheSecrets.")
        outputLengthBits = constants.SYMMETRIC_KEY_LENGTH_BITS * 8 # 8 keys of 256 bits each.
        hashFunction = Crypto.Hash.SHA256
        # Now pick the appropriate kx, kex values depending on the type of agent/peer.
        # Note that one peer never has the kx value of the other peer (it is a secret value).
        if self.agentType == constants.LOCATHE_LOCATION_SERVICE_AGENT_TYPE:
            kx = self.kr
            kex = self.kei
        else:
            kx = self.ki
            kex = self.ker

        self.sharedSecret = kex ** kx
        # Use the hash function after computing sharedSecret such that the pairing.Element, a point in an ellyptic curve, can be converted to a single value as bytes.
        # Bytes is the only type accepted by the hash functions.
        # Order of input is important here for all prf functions.
        #keySeed = Crypto.Hash.HMAC.new(ni + nr, hashPairSha256(sharedSecret), digestmod=hashFunction).digest()
        keySeed = locationserviceutility.prf(self.ni + self.nr, hashPair(self.sharedSecret), hashFunction=hashFunction)
        keyMaterial = locationserviceutility.prfPlus(keySeed, self.ni + self.nr + self.spii + self.spir, outputLengthBits=outputLengthBits)
        #self.sharedSecret, keyMaterial = locationserviceutility.computeEcdheSecrets(kx, kex, self.ni, self.nr, self.spii, self.spir, outputLengthBits, hashFunction=Crypto.Hash.SHA256)
        if debug: print(self.agentType, ": sharedSecret: ", self.sharedSecret)
        if debug: print(self.agentType, ": keyMaterial: ", keyMaterial)
        # Extract the secret session keys from the keyMaterial. Order is imperative.
        self.skai = keyMaterial[:31]
        self.skar = keyMaterial[32:63]
        self.skei = keyMaterial[64:95]
        self.sker = keyMaterial[96:127]
        self.skpi = keyMaterial[128:159]
        self.skpr = keyMaterial[160:191]
        self.sksauth = keyMaterial[192:223]
        self.sktoken = keyMaterial[224:255]
        if debug: print(self.agentType, ": created shared secrets.")

    def processTier1PrivacyAuthentication(self):
        """
        Do Tier_1_Privacy_Authentication.
        """
        return Status.NOT_IMPLEMENTED, {}

    def processTier2PrivacyAuthentication(self):
        """
        Do Tier_2_Privacy_Authentication.
        """
        return Status.NOT_IMPLEMENTED, {}

    def processTier2PrivacyAuthenticationAdditionalAuthenticationFactors(self):
        """
        Do Tier_2_Privacy_Authentication Additional Authentication Factors, gather additional authentication factors.
        """
        return Status.NOT_IMPLEMENTED, {}

    def processTier2PrivacyAuthenticationLPK_LSK(self):
        """
        Do Tier_2_Privacy_Authentication compute/send/receive LPK/LSK keys.
        """
        return Status.NOT_IMPLEMENTED, {}

    def processExchangeAuthenticationJointFactorKeyGeneration(self):
        """
        Do final Exchange Authentication, JointFactorKey generation.
        """
        return Status.NOT_IMPLEMENTED, {}

    def processAuthenticatedHandoff(self):
        """
        Process the State.AUTHENTICATED_HANDOFF state.

        In general, in this state the Location Service will sent its final AUTHr payload and then consider the user properly authenticated. Connection then
        proceeds with more data or by "handing off" to other medium.

        Returns
        -------
        IntNum, dict
            Status of processing this state.
            The response payload received from the other peer, if any.
        """
        return Status.NOT_IMPLEMENTED, {}

    def runProtocol(self):
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
        return None

    def start(self, kwargs={}):
        """
        Starts the agent at the initial state and possibly a few default options.

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

    def sendMessage(self, exchangeType, messageType, payload):
        """
        Aids in preparing a message to send through a socket, i.e., serializing the dictionary that composes the payload
        and sending through the connection socket.

        The JSON serializer will utilize jsonhelper.KeyEncoder to serialize pairing.Element objects, if present.

        Parameters
        ----------
        exchangeType : int
            The type of exchange to which this message belongs.
        messageType : bool
            True if it is a response message, False if it is a request message.
        payload : dict
            Dictionary containing the payload to serialize and send.

        Returns
        -------
        byte str
            The raw message that will be sent through the socket. Returning the exact raw message facilitates the calculation of <SignedOctets> by the
            protocol.

        Notes
        -----
        See http://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data

        """
        rawMessage = locationserviceutility.sendMessage(self.spii, self.spir, exchangeType, messageType, self.senderType, self.currentSendingMessageCounter, payload, self.sendMessageBytesSocket, self.groupObject.param)
        self.currentSendingMessageCounter += 1
        if debug: print(self.agentType, " simulator, send raw message:\n", rawMessage)
        return rawMessage

    def sendEncryptedMessage(self, exchangeType, messageType, payload):
        """
        Aids in preparing an encrypted message to send through a socket, i.e., serializing the dictionary that composes the payload
        and sending through the connection socket. It uses the agent's one-way DH secret shared key for encryption.

        The JSON serializer will utilize jsonhelper.KeyEncoder to serialize pairing.Element objects, if present.

        Parameters
        ----------
        exchangeType : int
            The type of exchange to which this message belongs.
        messageType : bool
            True if it is a response message, False if it is a request message.
        payload : dict
            Dictionary containing the payload to serialize and send.

        Returns
        -------
        byte str
            The raw message that will be sent through the socket. Returning the exact raw message facilitates the calculation of <SignedOctets> by the
            protocol.

        Notes
        -----
        See http://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data

        """
        # Location Service is the responder.
        if debug: print(self.agentType, " simulator, send encrypted message: plaintext is:\n", payload)
        secretKey = self.sker if self.agentType == constants.LOCATHE_LOCATION_SERVICE_AGENT_TYPE else self.skei
        rawMessage = locationserviceutility.sendEncryptedMessage(self.spii, self.spir, exchangeType, messageType, self.senderType, self.currentSendingMessageCounter, payload, self.sendMessageBytesSocket, self.groupObject.param, secretKey)
        self.currentSendingMessageCounter += 1
        if debug: print(self.agentType, " simulator, send encrypted raw message:\n", rawMessage)
        return rawMessage

    def sendMessageAttackTest(self, spii=None, spir=None, exchangeType=None, messageType=None, senderType=None,
                              currentSendingMessageCounter=None, payload=None):
        """
        This function performs similarly to the sendMessage funcion in this module, however it permits setting all relevant parameters
        manually, thus bypassing the automatic value selection from function sendMessage.

        In particular, the function permits manually setting spii, spir, senderType, and the message counter. The purpose is to craft
        a message to attack the protocol on the other peer, and thus test the other peer's reaction to the crafted message.
        For instance, one can change the message counter, or tamper with the message type, and verify the result.

        The message counter is not updated with this function.

        The payload is serialized into a JSON object, as it would normally happen with a legitimate message, and also the header is
        constructed with the manually set values.

        Parameters
        ----------
        spii : byte str, optional
            Security Parameter Index of the Initiator
        spir : byte str, optional
            Security Parameter Index of the Responder
        exchangeType : int
            The type of exchange to which this message belongs.
        messageType : bool
            True if it is a response message, False if it is a request message.
        senderType : bool, optional
            True if this message was generated by the Initiator; False if this message was generated by the Responder.
        currentSendingMessageCounter : int, optional
            Message counter.
        payload : dict
            Dictionary containing the payload to serialize and send.

        Returns
        -------
        byte str
            The raw message that will be sent through the socket. Returning the exact raw message facilitates the calculation of <SignedOctets> by the
            protocol.

        Notes
        -----
        See http://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data

        """
        # Define default argument values if None is passed.
        if spii is None:
            spii = self.spii
        if spir is None:
            spir = self.spir
        if senderType is None:
            senderType = self.senderType
        if currentSendingMessageCounter is None:
            currentSendingMessageCounter = self.currentSendingMessageCounter
        
        rawMessage = locationserviceutility.sendMessage(spii, spir, exchangeType, messageType, senderType, currentSendingMessageCounter, payload, self.sendMessageBytesSocket, self.groupObject.param)
        # Do not update the message counter.
        #self.currentSendingMessageCounter += 1
        if debug: print(self.agentType, " simulator, Attack Mode: send raw message:\n", rawMessage)
        return rawMessage

    def sendEncryptedMessageAttackTest(self, spii=None, spir=None, exchangeType=None, messageType=None, senderType=None,
                                       currentSendingMessageCounter=None, payload=None, sessionKey=None):
        """
        This function performs similarly to the sendEncryptedMessage funcion in this module, however it permits setting all relevant parameters
        manually, thus bypassing the automatic value selection from function sendEncryptedMessage.

        In particular, the function permits manually setting spii, spir, senderType, and the message counter. The purpose is to craft
        a message to attack the protocol on the other peer, and thus test the other peer's reaction to the crafted message.
        For instance, one can change the message counter, or tamper with the message type, and verify the result.

        The message counter is not updated with this function.

        The payload is serialized into a JSON object, as it would normally happen with a legitimate message, and also the header is
        constructed with the manually set values. The payload is still encrypted normally.

        Parameters
        ----------
        spii : byte str, optional
            Security Parameter Index of the Initiator
        spir : byte str, optional
            Security Parameter Index of the Responder
        exchangeType : int
            The type of exchange to which this message belongs.
        messageType : bool
            True if it is a response message, False if it is a request message.
        senderType : bool, optional
            True if this message was generated by the Initiator; False if this message was generated by the Responder.
        currentSendingMessageCounter : int, optional
            Message counter.
        payload : dict
            Dictionary containing the payload to serialize and send.
        sessionKey : byte str, optional
            The secret session key for payload encryption.


        Returns
        -------
        byte str
            The raw message that will be sent through the socket. Returning the exact raw message facilitates the calculation of <SignedOctets> by the
            protocol.

        Notes
        -----
        See http://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data

        """
        # Define default argument values if None is passed.
        if spii is None:
            spii = self.spii
        if spir is None:
            spir = self.spir
        if senderType is None:
            senderType = self.senderType
        if currentSendingMessageCounter is None:
            currentSendingMessageCounter = self.currentSendingMessageCounter
        # Location Service is the responder.
        if debug: print(self.agentType, " simulator, Attack Mode: send encrypted message: plaintext is:\n", payload)
        if sessionKey is None:
            secretKey = self.sker if self.agentType == constants.LOCATHE_LOCATION_SERVICE_AGENT_TYPE else self.skei
        else:
            secretKey = sessionKey
        rawMessage = locationserviceutility.sendEncryptedMessage(spii, spir, exchangeType, messageType, senderType, currentSendingMessageCounter, payload, self.sendMessageBytesSocket, self.groupObject.param, secretKey)
        # Do not update message counter.
        #self.currentSendingMessageCounter += 1
        if debug: print(self.agentType, " simulator, Attack Mode: send encrypted raw message:\n", rawMessage)
        return rawMessage


    def receiveMessageDeprecated(self):
        """
        Receives a message from the socket and deserializes it before returning it.


        Returns
        -------
        dict
            Deserialized message received from the socket.

        Notes
        -----
        See http://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data
        """
        self.expectedReceivedMessageCounter += 1
        return locationserviceutility.receiveMessage(self.locauthServer.receiveMessageFromConnectionSocketBytes)
        #return locationserviceutility.receiveAndDeserializePayload(self.locauthServer.receiveMessageFromConnectionSocketBytes)

    def receiveMessage(self, exchangeType, messageType, enforceSpiCheck=True):
        """
        Receives a message from the socket and deserializes it before returning it. It also validates the header and returns True if the header is OK, False otherwise.
        The message is always returned regardless of the validity of the header.


        Parameters
        ----------
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
        dict, bool
            dict: Deserialized message received from the socket. Or {} if the connection was closed by other peer.
            bool: True if header is valid, i.e., all values are those expected. False otherwise.

        Notes
        -----
        See http://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data
        """
        self.expectedReceivedMessageCounter += 1
        message = locationserviceutility.receiveMessage(self.receiveMessageBytesSocket)
        # Detect whether nothing was received, signifying a closed connection.
        if not message:
            return {}, False
        isHeaderValid = self.validateMessageHeader(message[constants.HEADER_FIELD_NAME], exchangeType, messageType, enforceSpiCheck=enforceSpiCheck)
        return message, isHeaderValid

    def receiveEncryptedMessage(self, exchangeType, messageType, enforceSpiCheck=True):
        """
        Receives an encrypted message from the socket and deserializes it before returning it. It also validates the header and returns True if the header is OK, False otherwise.
        The message is always returned regardless of the validity of the header.
        The function uses the one-way DH shared key to decrypt the message from the other peer.

        Parameters
        ----------
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
        dict, bool
            dict: Deserialized message received from the socket. Or {} if connection was closed by other peer.
            bool: True if header is valid, i.e., all values are those expected. False otherwise.

        Notes
        -----
        See http://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data
        """
        secretKey = self.skei if self.agentType == constants.LOCATHE_LOCATION_SERVICE_AGENT_TYPE else self.sker
        self.expectedReceivedMessageCounter += 1
        # Location Service is the responder. Use initiator key.
        message = locationserviceutility.receiveEncryptedMessage(self.receiveMessageBytesSocket, secretKey)
        # If empty, connection was closed by other peer. Return empty dict and False header.
        if not message:
            return {}, False
        if debug: print(self.agentType, ": receiveEncryptedMessage dict:\n", message)
        isHeaderValid = self.validateMessageHeader(message[constants.HEADER_FIELD_NAME], exchangeType, messageType, enforceSpiCheck=enforceSpiCheck)
        return message, isHeaderValid

    def validateMessageHeader(self, header, exchangeType, messageType, enforceSpiCheck=True):
        """
        Validates the header of a received message, i.e., checks whether SPI values match, the expected message counter is correct, whether the exchangeType is the one expected,
        the messageType is the one expected, the message sender is the initiator.

        This is not an inner, sub-level dictionary, but an outer, first level dictionary, i.e., [header_field] : value, [header_field]: value, etc.

        Parameters
        ----------
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
        return locationserviceutility.validateMessageHeader(self, header, exchangeType, messageType, enforceSpiCheck=enforceSpiCheck)

    def closeConnection(self):
        """
        Terminate connection.
        """
        self.closeSocket()
        return Status.CONNECTION_CLOSED, {}

    def computeSignedOctets(self, rawMessage, nValue, idPayloadSender, idPayloadRecipient, prfKey, hashFunction=Crypto.Hash.SHA256):
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

        From python IKE example:
        ...
        signed_octets = bytes(self.packets[0]) + self.Nr + prf(self.SK_pi, id_payload._data)
        packet.add_payload(payloads.AUTH(signed_octets))
        ...

        However, we are modifying the calculation as follows.BaseException

        Original:
        InitiatorSignedOctets = RealMessage1 | NonceRData | MACedIDForI
        ResponderSignedOctets = RealMessage2 | NonceIData | MACedIDForR

        To address the issue described in:
        From paper: Key Exchange in IPsec revisited: Formal Analysis of IKEv1 and IKEv2
        Also from book: Protocols for Authentication and Key Establishment, by Colin Boyd, Anish Mathuria, page 177.
        Even though I am not sure IKEv2 is affected by the weakness, I propose modify the protocol such that both ID payloads
        are included in the SignedOctets block and thus authenticated with the prf.

        We will also include the ID payloads in different order respective to the sender-recipient, i.e., the computation will now be:

        InitiatorSignedOctets = RealMessage1 | NonceRData | MACed(IDForI | IDForR)
        ResponderSignedOctets = RealMessage2 | NonceIData | MACed(IDForR | IDForI)

        Note that we are *not* doing:

        InitiatorSignedOctets = RealMessage1 | NonceRData | MACedIDForI | MACedIDForR
        ResponderSignedOctets = RealMessage2 | NonceIData | MACedIDForR | MACedIDForI

        The prf (MAC) includes the concatenation of both IDs, instead of the SignedOctets including a concatenation of individual
        prfs of IDi and IDr. I am unsure whether one format is "more secure" than the other. The resulting <SignedOctets> will be
        transformed by a prf, nevertheless.

        Of course, only in Tier 2 can this be accomplished, since only at Tier 2 Idi is revealed. In our implementation,
        Tier 1 AUTH values include an anonymous IDi as payload. Therefore, we will continue with this choice, unmodified.


        Parameters
        ----------
        rawMessage : byte str
            The raw message wherein Diffie-Helmann values were exchanged and was not protected by encryption. Usually the first message exchanged.
        nValue : byte str
            The nonce value provided by the other party, which this party will authenticate as the one received.
        idPayloadSender : byte str
            The id payload of the sender party of the AUTH payload which will contain the SignedOctets.
        idPayloadRecipient : byte str
            The id payload of the recipient party or peer of the AUTH payload which will contain the SignedOctets..
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
        return rawMessage + nValue + locationserviceutility.prf(prfKey, idPayloadSender + idPayloadRecipient, hashFunction=hashFunction)

    def computeAuthTier1i(self):
        """
        Computes the AUTH_TIER1i value, together with the auxiliary values (such as <SignedOctets>).

        Returns
        -------
        byte str
            AUTH_TIER1i value.
        """
        # AUTH_TIER1_i = prf(prf+(Ni | Nr, “LocAuth Tier_1” | Nb), <SignedOctets_i> | KEr).
        # signed_octets = bytes(self.packets[0]) + self.Nr + prf(self.SK_pi, id_payload._data)
        signedOctets = self.computeSignedOctets(self.messageContainer[constants.SIGNED_OCTETS_KEI_NI_RAW_MESSAGE], self.nr, self.messageContainer[constants.SIGNED_OCTETS_IDI_PAYLOAD_TIER1], self.messageContainer[constants.SIGNED_OCTETS_IDR_PAYLOAD], self.skpi)
        # Before computing AUTH value, certain values must be converted to appropriate byte str, such as KEx values that are (x,y) points.
        authTier1i = locationserviceutility.computeAuthTier(constants.LOCATHE_TIER1_AUTH_LITERAL_STRING, signedOctets, self.ni, self.nr, self.currentNb, self.ker)
        return authTier1i

    def computeAuthTier1r(self):
        """
        Computes the AUTH_TIER1r value, together with the auxiliary values (such as <SignedOctets>).

        Returns
        -------
        byte str
            AUTH_TIER1r value.
        """
        # AUTH_TIER1_r=prf(prf+(Ni | Nr, “LocAuth Tier_1” | Nb), <SignedOctets_r> | KEi).
        # signed_octets = bytes(self.packets[0]) + self.Ni + prf(self.SK_pr, id_payload._data)
        signedOctets = self.computeSignedOctets(self.messageContainer[constants.SIGNED_OCTETS_KER_NR_RAW_MESSAGE], self.ni, self.messageContainer[constants.SIGNED_OCTETS_IDR_PAYLOAD], self.messageContainer[constants.SIGNED_OCTETS_IDI_PAYLOAD_TIER1], self.skpr)
        # Before computing AUTH value, certain values must be converted to appropriate byte str, such as KEx values that are (x,y) points.
        authTier1r = locationserviceutility.computeAuthTier(constants.LOCATHE_TIER1_AUTH_LITERAL_STRING, signedOctets, self.ni, self.nr, self.currentNb, self.kei)
        return authTier1r

    def computeAuthTier2i(self):
        """
        Computes the AUTH_TIER2i value, together with the auxiliary values (such as <SignedOctets>).

        Authentication Tier 2:
        Spwd = prf(“LocAuth Tier_2”, UserKey)
        Kpwd = prf+(Ni | Nr, Spwd)
        s = random
        ENONCE = Encrypt_Kpwd(s)  // non-authenticated.
        GE = sAuth*G + SharedSecret
        AUTH_TIER2_i=prf(prf+(Ni | Nr, “LocAuth Tier_2” | Nb), <SignedOctets_i> | KEr)
        Create pair LSK_i, LPK_i // (LPK_i = LSK_i * GE)

        Returns
        -------
        byte str
            AUTH_TIER2i value.
        """
        signedOctets = self.computeSignedOctets(self.messageContainer[constants.SIGNED_OCTETS_KEI_NI_RAW_MESSAGE], self.nr, self.messageContainer[constants.SIGNED_OCTETS_IDI_PAYLOAD_TIER2], self.messageContainer[constants.SIGNED_OCTETS_IDR_PAYLOAD], self.skpi)
        authTier2i = locationserviceutility.computeAuthTier(constants.LOCATHE_TIER2_AUTH_LITERAL_STRING, signedOctets, self.ni, self.nr, self.currentNb, self.ker)
        return authTier2i

    def computeAuthTier2r(self):
        """
        Computes the AUTH_TIER2r value, together with the auxiliary values (such as <SignedOctets>).

        The AUTH_TIER2r is not originally presented in LOCATHE. We might however implement it if we allow a user agent to skip TIER 1 Authentication
        and go straight to Tier 2.

        Returns
        -------
        byte str
            AUTH_TIER2r value.
        """
        # AUTH_TIER2_r=prf(prf+(Ni | Nr, TIER2_STRING_LITERAL | Nb), <SignedOctets_r> | KEi)
        signedOctets = self.computeSignedOctets(self.messageContainer[constants.SIGNED_OCTETS_KER_NR_RAW_MESSAGE], self.ni, self.messageContainer[constants.SIGNED_OCTETS_IDR_PAYLOAD], self.messageContainer[constants.SIGNED_OCTETS_IDI_PAYLOAD_TIER2], self.skpr)
        # Before computing AUTH value, certain values must be converted to appropriate byte str, such as KEx values that are (x,y) points.
        authTier2r = locationserviceutility.computeAuthTier(constants.LOCATHE_TIER2_AUTH_LITERAL_STRING, signedOctets, self.ni, self.nr, self.currentNb, self.kei)
        return authTier2r

    def computeLskLpkPairAndGe(self, lskLengthBits=constants.LSK_LENGTH_BITS):
        """
        Computes the LSK (secret)/LPK (public) pair of secret shared keys, per LOCATHE protocol.
        The initiator (user) has LSKi, LPKi; responder (Location Service) has LSKr, LPKr.
        The function will compute the GE value and store it into the instance variable self.ge for later use
        (in particular, for computing GTK, which uses a token authenticator). The function will, in addition to
        returning the pair of keys, store them into respective instance variables.
        The sAuth value is retrieved from the respective instance variable.

        The keys as computed as follows:
            GE = sAuth*G + SharedSecret (EC arithmetic)
            LPK_i = LSK_i * GE
            LPK_r = LSK_r * GE

        GE is a pairing.Element object. sAuth is a (from a byte str) number. G is the global group generator, a pairing.Element object.

        Parameters
        ----------
        lskLengthBits : int, optional
            The length in bits of the computed LSK and LPK keys.

        Returns
        -------
        long int, pairing.Element object
            The long int is the secret key LSK.
            The pairing.Element is the public key LPK.
        """
        # We use modular exponenentiation. Charm converts appropriately to EC arithmetic.
        # Save the GE for later use.
        self.ge = (self.globalParameter['g'] ** int.from_bytes(self.sAuth['value'], "big")) * self.sharedSecret
        lsk = Crypto.Random.random.getrandbits(lskLengthBits) # scalar.
        lpk = self.ge ** lsk # pairing.Element.
        if self.agentType == constants.LOCATHE_LOCATION_SERVICE_AGENT_TYPE:
            # Location Service is the responder. Initiator never knows the lskr value.
            self.lskr = lsk
            self.lpkr = lpk
        else:
            # User agent is the initator. Responder never knows the lski value.
            self.lski = lsk
            self.lpki = lpk
        if debug: print(self.agentType, ": LSK:\n", lsk, "\nLPK:\n", lpk)
        self.log.info("%s: LSK/LPK pair generated.", self.agentType)
        return lsk, lpk

    def computeSpwd(self, key):
        """
        Computes the Stored Password (Spwd) value from the user's secret key, retrieved from the database.
        The secret key is typically a PBKDF2 salted password hash.

        The Spwd is computed as follows:

            Spwd = prf(“Spwd literal string”, UserKey)

        Parameters
        ----------
        key : byte str
            The user's secret key, previously retrieved from the database.

        Returns
        -------
        byte str
            the Spwd value derived from the key.
        """
        return locationserviceutility.prf(constants.LOCATHE_TIER2_SPWD_LITERAL_STRING, key)

    def computeKpwd(self, spwd, length=constants.KPWD_LENGTH_BITS):
        """
        Computes the Kpwd (Key from Password) value from the previously computed Spwd.
        Whereas the Spwd is a deterministic value, the Kpwd is dependent on the secret session established between the peers.
        The Kpwd will further be utilized to compute the ENONCE.

        Kpwd is computed as follows:
            Kpwd = prf+(Ni | Nr, Spwd)

        Parameters
        ----------
        spwd : byte str
            Spwd value computed from the user's secret key.
        length : int, optional
            The length, in bits, for the computed Kpwd. This length is communicated to the underlying prf+.

        Returns
        -------
        byte str
            The Kpwd value.
        """
        return locationserviceutility.prfPlus(self.ni + self.nr, spwd, outputLengthBits=length)

    def computeSpwdThenKpwd(self, key, length=constants.KPWD_LENGTH_BITS):
        """
        Computes the Stored Password (Spwd) value from the user's secret key, retrieved from the database..
        Then, computes the Kpwd (Key from Password) value from the previously computed Spwd.

        This function essentially combines the individual functions computeSpwd() and computeKpwd() into one.

        Whereas the Spwd is a deterministic value, the Kpwd is dependent on the secret session established between the peers.
        The Kpwd will further be utilized to compute the ENONCE.

        The Spwd is computed as follows:

            Spwd = prf(“Spwd literal string”, UserKey)

        Kpwd is computed as follows:

            Kpwd = prf+(Ni | Nr, Spwd)

        Parameters
        ----------
        key : byte str
            The user's secret key, previously retrieved from the database.
        length : int, optional
            The length, in bits, for the computed Kpwd. This length is communicated to the underlying prf+.

        Returns
        -------
        byte str
            The Kpwd value.

        Notes
        -----
        This function essentially combines the individual functions computeSpwd() and computeKpwd() into one.
        """
        return self.computeKpwd(self.computeSpwd(key), length=length)

    def computeEnonce(self, kpwd, sNonceLengthBits=constants.RANDOM_SECRET_LENGTH_BITS):
        """
        Computes the ENONCE value, typically for the user agent. The Location Service agent is interested in the s value from the decryption of
        the ENONCE.

        ENONCE is computed as follows:
            ENONCE = Encrypt_Kpwd(sNonce)  // non-authenticated.

        This function generates a random nonce s, and then encrypts it, resulting in the ENONCE. The encryption of the nonce s is done in
        non-authenticated mode to mitigate an offline password attack on the ENONCE. If the encryption is AEAD, an attacker could build a
        decryption oracle a simply verify guesses by validating the authentication. Obviously, the attacker first has to obtain the ENONCE
        by attacking the session encryption first.

        The encrytion algorithm here is AES-CBC: we utilize Charm's symcrypto SymmetricCryptoAbstraction as module.

        Parameters
        ----------
        kpwd : byte str
            The symmetric key to utilize for encryption.

        Returns
        -------
        dict (enonce), byte str (sNonce)
            dict is the Charm symcrypto dict style of ciphertext.
             {'ALG': symmetric cryptosystem.
              'MODE': symmetric encryption mode.
              'IV': the IV for the encryption algorithm.
              'CipherText': the padded ciphertext (padding according to PKCS 7) and encoded in base64.
             }
            The byte str is the sNonce.
        """
        # Generate a random sNonce. Use non-AEAD encryption such that eNonce is not subject to offline password attack.
        sNonce = Crypto.Random.get_random_bytes(sNonceLengthBits // 8)
        cipher = charm.toolbox.symcrypto.SymmetricCryptoAbstraction(kpwd)
        eNonce = cipher.encrypt(sNonce)
        return eNonce, sNonce

    def computeKpwdThenEnonceUpdateSauthAndCurrentFactorScore(self, key, keyType):
        """
        Computes Spwd, Kpwd, generates the ENONCE, and updates the instance variable sAuth and currentFactorScore.

        Parameters
        ----------
        key : byte str
            Secret key from which Spwd, Kpwd will be computed.
        keyType : str
            keyType utilized to fetch the factorScore and update self.currentFactorScore

        Returns
        -------
        dict (enonce)
            dict is the Charm symcrypto dict style of ciphertext.
             {'ALG': symmetric cryptosystem.
              'MODE': symmetric encryption mode.
              'IV': the IV for the encryption algorithm.
              'CipherText': the padded ciphertext (padding according to PKCS 7) and encoded in base64.
             }
        """
        kpwd = self.computeSpwdThenKpwd(key)
        # Generate sNonce and ENONCE.
        eNonce, sNonce = self.computeEnonce(kpwd)
        # Given this ENONCE, update sAuth.
        self.updateSauth(sNonce)
        # Update current factor score.
        self.currentFactorScore += locationserviceutility.getKeyTypeFactorScore(keyType, database=self.agentObject.database)
        return eNonce

    def decryptEnonce(self, eNonce, kpwd):
        """
        Decrypts an ENONCE value (using kpwd) and returns the corresponding s (or sNonce) plaintext.

        The encryption of ENONCE is done in non-authenticated mode, As such, there is no way to authenticate decryption and
        verify whether the plaintext is truly the original one. In this version, the encryption is AES-CBC.

        Parameters
        ----------
        eNonce : dict
            The ENONCE in Charm Crypto dict style (see docstring for function computeEnonce()).
        kpwd : byte str
            The secret key KPwd for decryption.

        Returns
        -------
        byte str
            The corresponding s or sNonce value.
        """
        cipher = charm.toolbox.symcrypto.SymmetricCryptoAbstraction(kpwd)
        # Decrypt and convert to long int.
        return cipher.decrypt(eNonce)

    def decryptEnonceUpdateSauthAndCurrentFactorScore(self, key, message):
        """
        Computes Spwd, Kpwd, decrypts the ENONCE payload within the message, obtains sNonce, and updates the instance variable sAuth
        and currentFactorScore

        Parameters
        ----------
        key : byte str
            Secret key from which Spwd, Kpwd will be computed.
        message : dict
            The message from which the ENONCE and keyType will be retrieved.
        """
        kpwd = self.computeSpwdThenKpwd(key)
        # Decrypt ENONCE and fetch sNonce. sNonce is a byte str.
        sNonce = self.decryptEnonce(message[constants.PAYLOAD_FIELD_NAME_ENONCE], kpwd)
        # Given this sNonce, update sAuth.
        self.updateSauth(sNonce)
        # Update current factor score.
        self.currentFactorScore += locationserviceutility.getKeyTypeFactorScore(message[constants.PAYLOAD_FIELD_NAME_AUTHENTICATION_KEY_TYPE],
                                                                                database=self.agentObject.database)

    def constructIDiPayload(self, message):
        """
        Receives a message dict and constructs, from it, a single IDi payload in serialized, byte str format.
        This function aids in constructing the IDi payload for computing the AUTH_TIER2_i value.

        Parameters
        ----------
        message : dict
            The message in dictionary format. It must contain the constants.PAYLOAD_FIELD_NAME_ID_I key:value.

        Returns
        -------
        byte str
            The IDi payload, a byte str, serialized dict of constants.PAYLOAD_FIELD_NAME_ID_I: userID.
        """
        assert constants.PAYLOAD_FIELD_NAME_ID_I in message
        return json.dumps({constants.PAYLOAD_FIELD_NAME_ID_I: message[constants.PAYLOAD_FIELD_NAME_ID_I]}, cls=jsonhelper.KeyEncoder, pairingCurve=self.groupObject.param).encode()


    def updateBnonce(self):
        """
        Updates the current BNONCE related instance variables (BNONCE value, BNONCE serialized, BNONCE signature), generating new values if the current
        BNONCE values are expired per the BNONCE timer.

        This function should be called every time a BNONCE variable is utilized, such that it is ensured the BNONCE is always curent and the protocol
        operates as designed.

        Returns
        -------
        bool
            True if the current BNONCE values were updated per expiration of the timer.
            False if the current BNONCE values are still valid.

        Notes
        -----
        Is there a way to call this function periodically by an event manager. Since we cannot hide the BNONCE variables, nor deny them access by other
        python functions, if a programmer uses the variables directly, without calling this function, the LOCATHE protocol implementation will be defective.
        Likewise, there is no way to provide the current BNONCE values onlyl through the return of this function, because any static variable within
        the function is still accessible from the outside.
        """
#        # Check Nb validity timer.
#        # If expired, generate new Nb, BNONCE, and its signature, and store them for future reference.
#        if self.nbExpirationEpoch <= time.time(): # It is expired.
#            if debug: print("Location Server: BNONCE expired. Generating a new one...")
#            self.currentNb, self.currentBnonceSerialized, self.currentBnonceSignature = self.locationServiceObject.generateBnonce(self.bnonceAuthorityList, self.bnonceAccessPolicy, self.bnonceLengthBits)
#            if debug: print("Location Server: the Nb is: ", self.currentNb)
#            # Reset Nb validity timer.
#            self.nbExpirationEpoch = time.time() + self.defaultBroadcastExpirationSeconds
#            # Done. Return True since the values were updated.
#            return True
#        else:
#            # Done. Return False since the current values are still valid, nothing updated.
#            return False
        if debug: print(self.agentType, ": BNONCE expired. Generating a new one...")
        if debug: print("self.agentObject = ", self.agentObject)
        self.currentNb, self.currentBnonceSerialized, self.currentBnonceSignature = self.agentObject.generateBnonce(self.bnonceAuthorityList, self.bnonceAccessPolicy, self.bnonceLengthBits)
        if debug: print(self.agentType, ": the Nb is: ", self.currentNb)
        # Reset Nb validity timer.
        self.nbExpirationEpoch = time.time() + self.defaultBroadcastExpirationSeconds
        #self.bnonceScheduler.enter(self.defaultBroadcastExpirationSeconds, 1, self.updateBnonce)

    def scheduleBnonceUpdate(self):
        """
        Schedules the periodic update of BNONCE/Nb instance variables.

        At every self.nbExpirationEpoch, the function updates the instance variables related to BNONCE/Nb, such that every function that utilizes
        Nb are guaranteed to have updated values.
        """
        if debug: print(self.agentType, ": entering BNONCE scheduler...")
        self.updateBnonce()
        #self.bnonceScheduler.enter(self.defaultBroadcastExpirationSeconds, 1, self.updateBnonce)
        self.bnonceTimer = threading.Timer(constants.DEFAULT_BROADCAST_EXPIRATION_SECONDS, self.scheduleBnonceUpdate)
        self.bnonceTimer.start()

    def cleanUp(self):
        """
        Stop timers, etc., before leaving the simulation.
        """
        # Log the number of active threads.
        self.log.info("%s: Active threads %s", self.agentType, threading.active_count())
        if debug: print(self.agentType, ": Active threads before cleaning up: ", threading.active_count())
        # Cancel timers.
        if self.agentType == constants.LOCATHE_LOCATION_SERVICE_AGENT_TYPE:
            self.bnonceTimer.cancel()

    def updateSauth(self, sNonce):
        """
        Updates the sAuth value, a cascading prf of each and all sNonce values, each generated for each authentication factor.
        Since it is a prf, both the values and the order are important such that the final digest is the same at both Location Service and user agents.

        The function uses self.sAuth instance variable.

        Computation is as follows:

        sAuth_1 = prf(key, sNonce_1 | 0x01)
        sAuth_2 = prf(key, sAuth_1 | sNonce_2 | 0x02)
        sAuth_3 = prf(key, sAuth_2 | sNonce_3 | 0x03)
        …
        sAuth_n = prf(key, sAuth_n-1 | sNonce_n | 0xn)

        sAuth_final = sAuth_n

        sAuth is {'value': long int, 'counter': int}


        Parameters
        ----------
        sNonce : byte str
            A value representing the sNonce. The function converts the value to bytes by:
            sNonce.to_bytes(math.ceil(sNonce.bit_length() / 8), "big")
            or Crypto.Util.number.long_to_bytes(sNonce)
            Convert back to long int as:
            int.from_bytes(value, "big")

        Notes
        -----
        The function uses self.sAuth instance variable.
        """
        #self.sNonceHash.update(sNonce.to_bytes(math.ceil(sNonce.bit_length() / 8), "big"))
        sAuthPrevious = self.sAuth['value']
        counter = self.sAuth['counter'] + 1
        sAuth = locationserviceutility.prf(self.sksauth, sAuthPrevious + sNonce + counter.to_bytes(math.ceil(counter.bit_length() /8), "big"))
        self.sAuth.update({'value': sAuth, 'counter': counter})

    def computeFinalAuthAndJointFactorKey(self, entityID):
        """
        Computes the final AUTHi and AUTHr values, and the JointFactorKey secret.

        TokenAuthenticatorInteger = prf(SK_stoken, TokenAuthenticator) # As long int.
        GTK = TokenAuthenticatorInteger * GE
        AuthSharedSecret = LSK_i * LPK_r
        AUTHi = prf(prf+(Ni | Nr, AuthSharedSecret), GTK | LPK_r)
        JointFactorKey = prf(Ni | Nr, LOCATHE_JFK_LITERAL| AuthSharedSecret)

        JointFactorKey will be utilized as the new pre-shared secret between parties.
        JointFactorKey should expire within one hour, and can be utilized in handoffs to other network media or subsequent authentications
        to other cells.

        Note hat the AUTH value comprises the AuthSharedSecret. The AuthSharedSecret is made from LSK/LPK values, which are computed from GE.
        GE is computed from sAuth, which is composed by authentication factors from the user. Thus, the AUTH value ultimately authenticates
        the user from the user's authentication factors that were presented during the protocol.

        GTK's purpose is solely to introduce the TokenAuthenticator into the AUTH value, in a manner that, even if the GTK value is
        disclosed, the "exponent" TokenAuthenticator is hard to be obtained according to the discrete logarithm problem.

        Parameters
        ----------
        entityID : str
            The user entityID whose TOTP token will be retrieved.
        lpk : pairing.Element
            The public part of the LPK/LSK pair. The Location Service will pass LPKi; the user agent will pass LPKr (i.e., the public key belonging to the other peer).
        lsk : long int
            The secret part of the LPK/LSK pair. The Location Service will pass LSKr; the user agent will pass LPKi (i.e., their own secret key).

        Returns
        -------
        byte str (AUTHi), byte str (AUTHr), byte str (JFK)
            The AUTHi value.
            The AUTHr value.
            The JointFactorKey.
        """
        tokenAuthenticator = locationserviceutility.getEntityCurrentTotpLocatheToken(entityID, database=self.agentObject.database)
        # Use the prf of the tokenAuthenticator with the appropriate shared secret and utilize the long integer of it to compute GTK.
        # The prf ensures the final value is large (256 bits) and as close as possible to random.
        # Typically, tokenAuthenticator value is rather small (6-8 digits), inappropriate for a secret key.
        tokenAuthenticatorInteger = int.from_bytes(locationserviceutility.prf(self.sktoken, tokenAuthenticator.to_bytes(math.ceil(tokenAuthenticator.bit_length() / 8), "big")), "big")
        gtk = self.ge ** tokenAuthenticatorInteger
        # Convert EC points to single values using hashPairSha256 from Crypto library (hashes a point into a byte str).
        # If this is the LocationService, the LocationService knows lskr and lpki.
        if self.agentType == constants.LOCATHE_LOCATION_SERVICE_AGENT_TYPE:
            authSharedSecretBytes = hashPair(self.lpki ** self.lskr)
        # Else, this is the user agent and it has lski and lpkr.
        else:
            authSharedSecretBytes = hashPair(self.lpkr ** self.lski)
        authi = locationserviceutility.prf(locationserviceutility.prfPlus(self.ni + self.nr, authSharedSecretBytes, constants.AUTH_PRFPLUS_KEY_LENGTH_BITS), hashPair(gtk) + hashPair(self.lpkr))
        authr = locationserviceutility.prf(locationserviceutility.prfPlus(self.ni + self.nr, authSharedSecretBytes, constants.AUTH_PRFPLUS_KEY_LENGTH_BITS), hashPair(gtk) + hashPair(self.lpki))
        # JointFactorKey computation is the same for both agents.
        jointFactorKey = locationserviceutility.prf(self.ni + self.nr, constants.LOCATHE_JOINT_FACTOR_KEY_LITERAL_STRING + authSharedSecretBytes)
        return authi, authr, jointFactorKey

    def registerJointFactorKey(self, userEntityID, jointFactorKey, expireExistingJFKs=True):
        """
        Registers the newly created JointFactorKey to the agent-respective database (Location Service or user agent). The database is
        evaluated automatically by the function from agentObject.database.

        Optionally, this function can expire existing, valid JFKs in the database, such that only one valid JFK exists for the
        userEntityID at a time. This action can be used to avoid raising the user's "trust" or maximum factor score too much, since a user
        could pool several valid JFKs to raise her maximum factor score. Unless the protocol only allows one JFK to be utilized at each time
        (that is the current behavior: only one key of each keyType can be presented by the user to the Location Service).

        Parameters
        ----------
        entityID : str
            The user entityID whose TOTP token will be retrieved.
        jointFactorKey : byte str
            The JointFactorKey to be registered to the database, belonging to the user.
        expireExistingJFKs : bool, optional
            If True, existing JFKs belonging to userEntityID will be expired before the new one is registered.
            If False, the new JFK is registered without touching any valid JFKs in the database.

        Returns
        -------
        bool
            **True** if the registration was successful; **False** if a similar record (but for the `lastTimeUsed`) was found.
        """
        # Expire existing JFKs if argument is True.
        if expireExistingJFKs:
            locationserviceutility.expireKeysOfType(userEntityID, [constants.LOCATHE_JOINT_FACTOR_KEY_KEY_TYPE], database=self.agentObject.database)
        # Now register the new JFK.
        expirationEpoch = time.time() + constants.DEFAULT_JOINT_FACTOR_KEY_SECRET_SECONDS
        return locationserviceutility.registerKeyToDatabase(userEntityID, jointFactorKey, b'', constants.LOCATHE_JOINT_FACTOR_KEY_KEY_TYPE, 'locathe JFK',
                                                            expirationEpoch=expirationEpoch, database=self.agentObject.database)