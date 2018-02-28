# -*- coding: utf-8 -*-
"""
Created on Wed May  6 12:46:05 2015

@author: locksmith
"""

import socket
from netservicetype import NetServiceType
import constants
import selectors

class NetService():
    """
    This is to test some network programming in Python.

    The class will contain all methods for both Server and Client modes. Let's
    see how to differentiate betweem the modes later.
    """

    def __init__(self, mode, destAddress, destPort=constants.DEFAULT_DESTINATION_TCP_PORT, srcPort=constants.DEFAULT_SOURCE_TCP_PORT):
        """
        Initialize the object with parameters.

        mode: "Server" or "Client".
        srcPort: TCP port for source. Only important for Server mode (listen port); Client mode will pick any from socket. (default=28880).
        destAddress: Destination IPv4 address.
        destPort: TCP port for destination. If Client, will typically use default Server listen. Of Server, will use the Client's specified one. (default=28880).
        """
        if (mode not in NetServiceType):
            raise ValueError("NetService __init__: mode must be one of ", list(NetServiceType))

        self.mode = mode
        self.destAddress = destAddress
        self.destPort = destPort
        self.srcPort = srcPort
        self.selector = selectors.DefaultSelector()


    def createSocket(self):
        """
        Create a socket for this object.

        Return: reference to created socket.

        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Cannot bind here, otherwise clients will not be able to connect.
        # self.localhost = socket.gethostbyname(socket.gethostname())
        # self.sock.bind((self.localhost, self.srcPort))
        return self.sock

    def listenForConnections(self, timeout=None):
        """
        Binds socket and listen to connections requests from Clients.

        Typically for servers, a new socket will be spawned and its reference saved to self.connectionSocket.

        Parameters
        ----------
        timeout : int
            If timeout > 0, this specifies the maximum wait time, in seconds, for a connection request to be heard.
            If timeout is None, the function will block until a connection request is received.

        Returns
        -------
        object, str
            connectionSocket socket reference, connection destination address.
            None, None in case of timeout.

        Notes
        -----
        If the listening socket times out, then (None, None) will be returned.
        """
        self.selector.register(self.sock, selectors.EVENT_READ, "connection request received")
        event = self.selector.select(timeout=timeout)
        if event:
            # Connection request received. Accept it.
            localhost = socket.gethostbyname(socket.gethostname())
            # Here, avoid binding the socket to the localhost, as it might restrict too much the networks to which the socket listens. In fact, I got
            # several "connection refused" in Linux by binding the socket to localhost. Suggested at
            # http://stackoverflow.com/questions/16130786/why-am-i-getting-the-error-connection-refused-in-python-sockets
            #self.sock.bind((localhost, self.srcPort))
            self.sock.bind(('', self.srcPort))
            self.sock.listen(1) # Listen here to incoming connections.
            #self.sock.settimeout(5) # 5 seconds timeout?
            self.connectionSocket, self.connectionDestAddress = self.sock.accept() # Accepts an incoming connection, populates the attributes.
            #print("Now connected to ", self.connectionDestAddress)
        else:
            # Timed out. Return with None, None (no connection socket).
            self.connectionSocket = None
            self.connectionDestAddress = None

        self.selector.unregister(self.sock)
        return self.connectionSocket, self.connectionDestAddress

    def connectToDestination(self):
        """
        Connect to destination through the socket.

        Typically for clients, the connection utilizes the same socket already created at createSocket().
        """
        self.sock.connect((socket.gethostbyname(self.destAddress), self.destPort))

    def receiveMessageFromConnectionSocket(self, timeout=None, bufferSize=constants.INET_RECEIVE_BUFFER_SIZE):
        """
        Receive messages through the connection (spawned) socket.

        Typically for use by the Server.

        Parameters
        ----------
        timeout : int, optional
            If timeout > 0, this specifies the maximum wait time for data to be received, in seconds.
            If timeout is None, the call will block until data is received.
        bufferSize : int, optional
            size of receive buffer

        Returns
        -------
        str
            message received (string), potentially "" (empty str).

        Notes
        -----
        For notes in using blocking recv sockets with selectors, see http://www.gossamer-threads.com/lists/python/dev/705514.
        """
        return self.receiveMessageFromConnectionSocketBytes(timeout=timeout, bufferSize=bufferSize).decode()

    def receiveMessageFromMainSocket(self, timeout=None, bufferSize=constants.INET_RECEIVE_BUFFER_SIZE):
        """
        Receive messages through the main (listening) socket.

        Typically for use by the Client.

        Parameters
        ----------
        timeout : int
            If timeout > 0, this specifies the maximum wait time for data to be received, in seconds.
            If timeout is None, the call will block until data is received.
        bufferSize : int, optional
            size of receive buffer

        Returns
        -------
        str
            message received (string), potentially "" (empty str).

        Notes
        -----
        For notes in using blocking recv sockets with selectors, see http://www.gossamer-threads.com/lists/python/dev/705514.
        """
        return self.receiveMessageFromMainSocketBytes(timeout=timeout, bufferSize=bufferSize).decode()

    def sendMessageThruMainSocket(self, outgoingMessage):
        """
        Send a message through the main (listing) socket.

        Typically for use by the Server.

        Parameters
        ----------
        outgoingMessage : str
            message to send.
        """
        self.sendMessageThruMainSocketBytes(outgoingMessage.encode())

    def sendMessageThruConnectionSocket(self, outgoingMessage):
        """
        Send a message through the connection (spawned) socket.

        Typically for use by the client.

        Parameters
        ----------
        outgoingMessage : str
            message to send.
        """
        self.sendMessageThruConnectionSocketBytes(outgoingMessage.encode())

    def receiveMessageFromConnectionSocketBytes(self, timeout=None, bufferSize=constants.INET_RECEIVE_BUFFER_SIZE):
        """
        Receive byte messages through the connection (spawned) socket.

        Typically for use by the Server.

        Parameters
        ----------
        timeout : int, optional
            If timeout > 0, this specifies the maximum wait time for data to be received, in seconds.
            If timeout is None, the call will block until data is received.
        bufferSize : int, optional
            size of receive buffer

        Returns
        -------
        byte str
            message received (string), potentially "" (empty str).

        Notes
        -----
        For notes in using blocking recv sockets with selectors, see http://www.gossamer-threads.com/lists/python/dev/705514.
        """
        self.selector.register(self.connectionSocket, selectors.EVENT_READ, "data received")
        event = self.selector.select(timeout=timeout)
        if event:
            incomingMessage = self.connectionSocket.recv(bufferSize)
        else:
            incomingMessage = b''
        #print("Incoming message:")
        #print(incomingMessage)
        self.selector.unregister(self.connectionSocket)
        return incomingMessage

    def receiveMessageFromMainSocketBytes(self, timeout=None, bufferSize=constants.INET_RECEIVE_BUFFER_SIZE):
        """
        Receive byte messages through the main (listening) socket.

        Typically for use by the Client.

        Parameters
        ----------
        timeout : int
            If timeout > 0, this specifies the maximum wait time for data to be received, in seconds.
            If timeout is None, the call will block until data is received.
        bufferSize : int, optional
            size of receive buffer

        Returns
        -------
        byte str
            message received (string), potentially "" (empty str).

        Notes
        -----
        For notes in using blocking recv sockets with selectors, see http://www.gossamer-threads.com/lists/python/dev/705514.
        """
        self.selector.register(self.sock, selectors.EVENT_READ, "data received")
        event = self.selector.select(timeout=timeout)
        if event:
            incomingMessage = self.sock.recv(bufferSize)
        else:
            incomingMessage = b''
        #print("Incoming message:")
        #print(incomingMessage)
        self.selector.unregister(self.sock)
        return incomingMessage

    def sendMessageThruMainSocketBytes(self, outgoingMessage):
        """
        Send a byte message through the main (listing) socket.

        Typically for use by the Server.

        Parameters
        ----------
        outgoingMessage : byte str
            byte message to send.
        """
        self.sock.sendall(outgoingMessage)

    def sendMessageThruConnectionSocketBytes(self, outgoingMessage):
        """
        Send a message through the connection (spawned) socket.

        Typically for use by the client.

        Parameters
        ----------
        outgoingMessage : byte str
            byte message to send.
        """
        self.connectionSocket.sendall(outgoingMessage)

    def closeConnectionSocket(self):
        """
        Terminates the connection and close socket.

        Only closes the connected socket. The listening socket from a Server
        is kept.
        """
        #self.connectionSocket.shutdown()
        self.connectionSocket.shutdown(socket.SHUT_RDWR)
        self.connectionSocket.close()

    def closeMainSocket(self):
        """
        Terminates the main socket.

        """
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()









