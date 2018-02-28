# -*- coding: utf-8 -*-
"""
Created on Tue Jun  9 15:50:40 2015

@author: locksmith
"""

import unittest
import unittest.mock
#import unittest.mock as mock
from bluetoothlayer import BluetoothNetService
from netservicetype import NetServiceType
import bluetooth

#@unittest.mock.patch('bluetoothlayer.bluetooth.BluetoothSocket', autospec=True) # Will the the *last* argument/patch in all test cases.
class TestBluetoothSocket(unittest.TestCase):

    #@unittest.mock.patch('bluetoothlayer.bluetooth.BluetoothSocket', autospec = True)
    def setUp(self):
        self._mode = NetServiceType.BLUETOOTH_SERVER
        # We can perhaps do some validity checks here for port numbers and etc. based on the selected mode.
        self._destAddress = None
        self._destPort = None
        # This below is deprecated. Just bind to port zero.
        #self.srcPort = bluetooth.get_available_port(bluetooth.RFCOMM) # Find available RFCOMM port.
        self._srcPort = bluetooth.PORT_ANY
        #self._uuid = "6d2eecb8-6675-47cb-a1c0-925ca12dae15" # Just a random 128-bit UUID.
        #self._uuid = "10caa7h0-beac01400-10ca7hebeac014000" # An attempt to write "locauth-beacon-locathebeacon" in hexspeak (with 0s for filling in).
        self._uuid = "10caa7h0-5e1271ce0-10ca7hebeac014000" # An attempt to write "locauth-service-locathebeacon" in hexspeak (with 0s for filling in).
        self._service = "LOCAUTH Service"
        # Set up bluetooth mock, create server and socket.
        self.patcher = unittest.mock.patch('bluetoothlayer.bluetooth.BluetoothSocket', autospec = True)
        self.mock_BluetoothSocket = self.patcher.start()
        self.server = BluetoothNetService(NetServiceType.BLUETOOTH_SERVER, uuid=self._uuid, service=self._service)
        self.server.createSocket()
        self.addCleanup(self.patcher.stop)

    #@unittest.mock.patch('bluetoothlayer.bluetooth.BluetoothSocket', autospec=True)
#==============================================================================
#     def test_createSocket(self, mock_BluetoothSocket):
#         # Test creation of socket.
#         server = BluetoothNetService(NetServiceType.BLUETOOTH_SERVER, uuid=self._uuid, service=self._service)
#         mock_BluetoothSocket.return_value = "socket created"
#         response = server.createSocket()
#         #print("createsocket", response)
#         self.assertEqual(response, mock_BluetoothSocket.return_value)
#         #server.listenForConnections()
#==============================================================================

    #@unittest.mock.patch.object(bluetoothlayer.bluetooth.BluetoothSocket, 'accept', autospec=True)
    #@unittest.mock.patch.object(bluetoothlayer.bluetooth.BluetoothSocket, 'listen', autospec=True)
    #@unittest.mock.patch.object(bluetoothlayer.bluetooth.BluetoothSocket, 'bind', autospec=True)
    @unittest.mock.patch('bluetoothlayer.bluetooth.advertise_service', autospec=True)
    #@unittest.mock.patch('bluetoothlayer.bluetooth.BluetoothSocket', autospec=True)
    def test_listenForConnections(self, mock_bluetooth_advertise_service):
                                  #mock_BluetoothSocket_bind, mock_BluetoothSocket_listen,
                                  #mock_BluetoothSocket_accept):
        # Test creation of socket.
        #print(mock_BluetoothSocket)
        #print(mock_advertise_service)
        self.mock_BluetoothSocket.return_value.listen.return_value = "listening"
        self.mock_BluetoothSocket.return_value.accept.return_value = ("connected socket object", "Mock test address: test_listenForConnections")
        self.mock_BluetoothSocket.return_value.bind.return_value = "bound"
        mock_bluetooth_advertise_service.return_value = "advertising service"
        # Do not mess with return value of Mock object here; it needs to remain a MagicMock object that will be used within bluetoothlayer.
        #mock_BluetoothSocket.return_value = "socket created"
        #server = BluetoothNetService(NetServiceType.BLUETOOTH_SERVER, uuid=self._uuid, service=self._service)
        #server.createSocket()
        response = self.server.listenForConnections()
        self.assertEqual(response, self.mock_BluetoothSocket.return_value.accept.return_value)

    @unittest.mock.patch('bluetoothlayer.bluetooth.find_service', autospec=True)
    def test_findServices(self, mock_bluetooth_find_service):
        mock_bluetooth_find_service.return_value = self._service + " found"
        #server = BluetoothNetService(NetServiceType.BLUETOOTH_SERVER, uuid=self._uuid, service=self._service)
        self.assertEqual(self.server.findServices(self._uuid), mock_bluetooth_find_service.return_value)

    def test_connectToDestination(self):
        #server = BluetoothNetService(NetServiceType.BLUETOOTH_SERVER, uuid=self._uuid, service=self._service)
        #server.createSocket()
        self.server.connectToDestination()
        # The connectToDestination method calls bluetooth.connect, which takes a (destAddress, destPort) pair as argument,
        # and returns nothing. Check whether this mocked method was actually called with the said pair.
        self.mock_BluetoothSocket.return_value.connect.assert_any_call((self._destAddress, self._destPort))

    @unittest.mock.patch('bluetoothlayer.bluetooth.advertise_service', autospec=True)
    def test_receiveMessageFromConnectionSocket(self, mock_bluetooth_advertise_service):
        self.mock_BluetoothSocket.return_value.recv.return_value = "message from other peer received, connection socket".encode() # Encode first; the method will decode it, thus returning it to a normal string.
        #server = BluetoothNetService(NetServiceType.BLUETOOTH_SERVER, uuid=self._uuid, service=self._service)
        # The choice here is to create an auxiliary server, such that we can create a socket out of it and use that
        # socket as return_value for the accept method. The auxiliary server does nothing else.
        # Alternatively, we could use the socket created within the server itself as a return_value, as in:
        # mock_BluetoothSocket.return_value.accept.return_value = (server.createSocket(), "Mock test address")
        # The line above would both create the socket and use it as return_value (not a problem since they are all mocks anyway).
        # I will go with the auxiliary method to show things as separate, although they are all mocks and do nothing anyway.
        auxiliaryServer = BluetoothNetService(NetServiceType.BLUETOOTH_SERVER, uuid=self._uuid, service=self._service)
        #server.createSocket()
        sock = auxiliaryServer.createSocket()
        self.mock_BluetoothSocket.return_value.accept.return_value = (sock, "Mock test address: test_receiveMessageFromConnectionSocket")
        self.server.listenForConnections()
        # Since the receiveMessageFromConnectionSocket method decodes the received string, we first encode the return value of recv
        # such that the above method will decode it and compare correctly as if they were all standard strings.
        self.assertEqual(self.server.receiveMessageFromConnectionSocket(), self.mock_BluetoothSocket.return_value.recv.return_value.decode())

    def test_receiveMessageFromMainSocket(self):
        self.mock_BluetoothSocket.return_value.recv.return_value = "message from other peer received, main socket".encode() # Encode first; the method will decode it, thus returning it to a normal string.
        # Since the receiveMessageFromMainSocket method decodes the received string, we first encode the return value of recv
        # such that the above method will decode it and compare correctly as if they were all standard strings.
        self.assertEqual(self.server.receiveMessageFromMainSocket(), self.mock_BluetoothSocket.return_value.recv.return_value.decode())

    def test_sendMessageThruMainSocket(self):
        self.mock_BluetoothSocket.return_value.send.return_value = "message sent through main socket"
        message = "Message to other peer: main socket"
        response = self.server.sendMessageThruMainSocket(message)
        self.mock_BluetoothSocket.return_value.send.assert_any_call(message.encode()) # Message is encoded by method, so we must assert with encoded version.
        self.assertEqual(response, self.mock_BluetoothSocket.return_value.send.return_value)

    @unittest.mock.patch('bluetoothlayer.bluetooth.advertise_service', autospec=True)
    def test_sendMessageThruConnectionSocket(self, mock_bluetooth_advertise_service):
        self.mock_BluetoothSocket.return_value.send.return_value = "message sent through connection socket"
        message = "Message to other peer: connection socket"
        auxiliaryServer = BluetoothNetService(NetServiceType.BLUETOOTH_SERVER, uuid=self._uuid, service=self._service)
        sock = auxiliaryServer.createSocket()
        self.mock_BluetoothSocket.return_value.accept.return_value = (sock, "Mock test address: test_sendMessageThruConnectionSocket")
        self.server.listenForConnections()
        response = self.server.sendMessageThruConnectionSocket(message)
        self.mock_BluetoothSocket.return_value.send.assert_any_call(message.encode()) # Message is encoded by method, so we must assert with encoded version.
        self.assertEqual(response, self.mock_BluetoothSocket.return_value.send.return_value)

    @unittest.mock.patch('bluetoothlayer.bluetooth.advertise_service', autospec=True)
    def test_closeConnectionSocket(self, mock_bluetooth_advertise_service):
        '''
        Test close methods for all types of sockets: main socket, connection socket, and main socket from a "client."
        Make use of side_effect to simulate three different return values from close methods.
        '''
        close_side_effects = ["closeMainSocket at server socket", "closeConnectionSocket at server socket", "closeMainSocket at auxiliary socket"]
        self.mock_BluetoothSocket.return_value.close.side_effect = close_side_effects
        auxiliaryServer = BluetoothNetService(NetServiceType.BLUETOOTH_SERVER, uuid=self._uuid, service=self._service)
        sock = auxiliaryServer.createSocket()
        self.mock_BluetoothSocket.return_value.accept.return_value = (sock, "Mock test address: test_closeConnectionSocket")
        self.server.listenForConnections()
        self.assertEqual(self.server.closeMainSocket(), close_side_effects[0])
        self.assertEqual(self.server.closeConnectionSocket(), close_side_effects[1])
        self.assertEqual(auxiliaryServer.closeMainSocket(), close_side_effects[2])

    def tearDown(self):
        pass

if __name__ == '__main__':
    unittest.main(verbosity=2)


