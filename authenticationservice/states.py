# -*- coding: utf-8 -*-
"""
Created on Thu May  5 11:14:02 2016

@author: locksmith
"""

# -*- coding: utf-8 -*-
"""
Created on Wed May  6 19:07:52 2015

@author: locksmith
"""
from enum import IntEnum, unique

@unique
class State(IntEnum):
    """
    Define States for LOCATHE finite-state machines.

    """

    START_IDLE = 0 # A start pseudo-state, does nothing but go to the first state.
    BROADCAST_ECDHE = 1 # The first phase of the LOCATHE protocol.
    BROADCAST_ECDHE_BLUETOOTH_ADVERTISEMENT = 2 # Submachine state within BROADCAST_ECDHE, comprises the Bluetooth Loc-Auth service advertisement.
    BROADCAST_ECDHE_ADVERTISEMENT_BLUETOOTH_LOCAUTH_ADVERTISEMENT = 3 # Submachine state within BROADCAST_ECDHE, comprises the Bluetooth Loc-Auth service advertisement.
    BROADCAST_ECDHE_BROADCAST_BNONCE = 4 # Submachime state, wherein the BNONCE is broadcast.
    BROADCAST_ECDHE_SEND_KER_NR = 5 #Submachine state, wherein KEr and Nr are sent.
    TIER1_PRIVACY_AUTHENTICATION = 6 # Tier 1 Privacy Authentication phase of LOCATHE. Tier 2 is supposedly optional.
    TIER2_PRIVACY_AUTHENTICATION = 7 # Tier 2 Privacy Authentication phase of LOCATHE. Tier 1 must have been completed successfully.
    TIER2_PRIVACY_AUTHENTICATION_ADDITIONAL_AUTHENTICATION_FACTORS = 8 # Tier 2 Privacy Authentication Additional Authenticaiton Factors phase of LOCATHE. Additional authentication factors are collected here.
    TIER2_PRIVACY_AUTHENTICATION_LPK_LSK = 9 # Tier 2 Privacy Authentication phase wherein the LPK/LSK key pair is computed and (the public part) exchanged.
    EXCHANGE_AUTHENTICATION_JOINT_FACTOR_KEY_GENERATION = 10 # Last phase of LOCATHE protocol, wherein all communications are authenticated and a Joint Factor Key is generated.
    AUTHENTICATED_HANDOFF = 11 # All is authenticated through LOCATHE. Continue with communications, or handoff.
    LISTEN_FOR_CONNECTIONS = 12 # A helper state for the proof-of-concept simulation, in particular the agent simulators. Listen for connection requests before advertising service.
    CONNECT_TO_SERVICE = 13 # Helper state that requests a network connection to the Location Service.
    BROADCAST_ECDHE_RECEIVE_BNONCE = 14 # Submachine state within BROADCAST_ECDHE, wherein the user agent expects to receive the BNONCE payload from the Location Service.
    BROADCAST_ECDHE_SEND_KEI_NI = 15 #Submachine state, wherein KEi and Ni are sent.
    CLOSE_CONNECTIONS_AND_EXIT = 16 # Terminate all connections and exit.