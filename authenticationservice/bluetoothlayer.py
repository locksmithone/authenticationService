# -*- coding: utf-8 -*-
"""
Created on Wed May  6 12:46:05 2015

@author: locksmith
"""

import constants as constants
import bluetooth
import netservicetype
import logging

class BluetoothNetService(object):
    """
    This is to test some network programming in Python.

    The class will contain all methods for both Server and Client modes. Let's
    see how to differentiate betweem the modes later.
    """

    RECEIVE_BUFFER_SIZE = constants.BLUETOOTH_RECEIVE_BUFFER_SIZE # Receive buffer size for receiving messages.

    def __init__(self, mode, destAddress=None, destPort=None, uuid=constants.LOCAUTH_UUID, service=constants.LOCAUTH_BLUETOOTH_SERVICE_DESCRIPTION):
        """
        Initialize the object with parameters.

        The source RFCOMM port will be chosen with the assistance of SDP server.

        mode: "Server" or "Client" or "Bluetooth_Server" or "Bluetooth_Client".
        destAddress: Destination Bluetooth device address.
        destPort: RFCOMM port for destination. If Client, will typically use default Server listen. Of Server, will use the Client's specified one. (default=2).
        uuid: uuid of the server service.
        service: text description of the service.
        """
        # Set filename and logging level for log messages.
        FORMAT = "%(asctime)s;%(levelname)s;%(message)s"
        DATEFORMAT = '%Y-%m-%d %H:%M:%S'
        #self.LOGFILE = logFile
        #self.LOGFILE = logFile
        #logging.basicConfig(filename=self.LOGFILE, level=logging.DEBUG, format=FORMAT, datefmt=DATEFORMAT)
        #logging.basicConfig(level=logging.DEBUG, format=FORMAT, datefmt=DATEFORMAT)
        formatter = logging.Formatter(fmt=FORMAT, datefmt=DATEFORMAT)
        self.log = logging.getLogger(__name__)
        handler = logging.FileHandler(__name__+'.log')
        self.log.setLevel(logging.DEBUG)
        handler.setFormatter(formatter)
        self.log.addHandler(handler)

        if (mode not in netservicetype.NetServiceType):
            raise ValueError("NetService __init__: mode must be one of ", list(netservicetype.NetServiceType))
            self.log.error("NetService __init__: mode must be one of %s", list(netservicetype.NetServiceType))

        self._mode = mode
        # We can perhaps do some validity checks here for port numbers and etc. based on the selected mode.
        self._destAddress = destAddress
        self._destPort = destPort
        # This below is deprecated. Just bind to port zero.
        #self.srcPort = bluetooth.get_available_port(bluetooth.RFCOMM) # Find available RFCOMM port.
        self._srcPort = bluetooth.PORT_ANY
        self._uuid = uuid # "1e0ca4ea-299d-4335-93eb-27fcfe7fFEFF" # Check here for UUID generation: https://www.uuidgenerator.net/
        self._service = service

    def createSocket(self):
        """
        Create a Bluetooth socket for this object.

        Return: reference to created socket.

        """
        self._sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
        #self.sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
        # Cannot bind here, otherwise clients will not be able to connect.
        # self.localhost = socket.gethostbyname(socket.gethostname())
        # self.sock.bind((self.localhost, self.srcPort))
        return self._sock

    def listenForConnections(self):
        """
        Binds socket and listen to connections requests from Clients.

        Typically for servers, a new socket will be spawned and its reference saved to self._connectionSocket.

        Return: connectionSocket reference, connection destination address.
        """
        #localhost = socket.gethostbyname(socket.gethostname())
        self._sock.bind(("", self._srcPort))
        self._sock.listen(1) # Listen here to incoming connections.

        #bluetooth.advertise_service( self.sock, "SampleServer",
                   #service_id = self.uuid)
                   #service_classes = [ self.uuid, bluetooth.SERIAL_PORT_CLASS ],
                   #profiles = [ bluetooth.SERIAL_PORT_PROFILE ])


        bluetooth.advertise_service(self._sock, self._service,
            service_id=self._uuid,
            service_classes=[self._uuid, bluetooth.LAN_ACCESS_CLASS],
            profiles=[bluetooth.LAN_ACCESS_PROFILE]) # Advertise some service here.
        self.log.info("Service: %s", self._service)
        self.log.info("UUID: %s", self._uuid)
        #print(self._service)
        #print(self._uuid)
        self._connectionSocket, self._connectionDestAddress = self._sock.accept() # Accepts an incoming connection, populates the attributes.
        self.log.info("Now connected to %s", self._connectionDestAddress)
        print("Now connected to ", self._connectionDestAddress)

        return self._connectionSocket, self._connectionDestAddress

    def findServices(self, uuid):
        """
        Find available services.
        """
        return bluetooth.find_service(uuid)
        #self.sock.connect((self.destAddress, self.destPort)) # Need a pair here, as opposed to two arguments as in network socket.

    def connectToDestination(self):
        """
        Connect to destination through the socket.

        Typically for clients, the connection utilizes the same socket already created at createSocket().
        """
        self._sock.connect((self._destAddress, self._destPort)) # Need a pair here, as opposed to two arguments as in network socket.
        #return (self._destAddress, self._destPort) # Return something here for test purposes

    def receiveMessageFromConnectionSocket(self):
        """
        Receive messages through the connection (spawned) socket.

        Typically for use by the Server.

        Return: message received (string).
        """
        incomingMessage = self._connectionSocket.recv(self.RECEIVE_BUFFER_SIZE).decode()
        #print("Incoming message:")
        #print(incomingMessage)
        return incomingMessage

    def receiveMessageFromMainSocket(self):
        """
        Receive messages through the main (listening) socket.

        Typically for use by the Client.

        Return: message received (string).
        """
        incomingMessage = self._sock.recv(self.RECEIVE_BUFFER_SIZE).decode()
        #print("Incoming message:")
        #print(incomingMessage)
        return incomingMessage

    def sendMessageThruMainSocket(self, outgoingMessage):
        """
        Send a message through the main (listing) socket.

        Typically for use by the Server.
        """
        return self._sock.send(outgoingMessage.encode())

    def sendMessageThruConnectionSocket(self, outgoingMessage):
        """
        Send a message through the connection (spawned) socket.

        Typically for use by the client.
        """
        return self._connectionSocket.send(outgoingMessage.encode())

    def closeConnectionSocket(self):
        """
        Terminates the connection and close socket.

        Only closes the connected socket. The listening socket from a Server
        is kept.
        """
        #self.connectionSocket.shutdown()
        return self._connectionSocket.close()

    def closeMainSocket(self):
        """
        Terminates the connection and close socket.

        Only closes the main socket.
        """
        #self.sock.shutdown()
        return self._sock.close()
