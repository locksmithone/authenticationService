#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Dec  1 16:53:14 2016

@author: locksmith
"""

from enum import IntEnum, unique

@unique
class NetServiceType(IntEnum):
    """
    Define types for NetService.
    
    Server -- Listens to connections.
    Client -- Initiates a connection to the Server.
    """
    SERVER = 1 # Listens to connections.
    CLIENT = 2 # Initiates a connection to the Server.
    BLUETOOTH_SERVER = 3 # Listens to connections from Bluetooth interface.
    BLUETOOTH_CLIENT = 4 # Initiates a connection to a Bluetooth peer.
    
