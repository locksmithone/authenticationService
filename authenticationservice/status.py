# -*- coding: utf-8 -*-
"""
Created on Wed Nov  30 19:07:52 2016

@author: locksmith
"""
from enum import IntEnum, unique

@unique
class Status(IntEnum):
    """
    Define status responses from states within LOCATHE protocol.
    """

    NB_TIMER_EXPIRED = 0
    CONNECTION_REQUEST_RECEIVED = 1
    INVALID_KEI_NI = 2
    TIMEOUT = 3
    KEI_NI_RECEIVED = 4
    INVALID_TIER1_PAYLOAD = 5
    ENCRYPTION_FAIL = 6
    INVALID_TIER2_PAYLOAD = 7
    INVALID_JFK_AUTH_PAYLOAD = 8 # Joint Factor Key, AUTH payload.
    TIER1_PHASE_OK = 9
    TIER2_PHASE_OK = 10
    AUTH_OK = 11 # Currently unused.
    INVALID_KER_NR = 12
    KER_NR_RECEIVED = 13

    INVALID_SPI = 14

    ERROR = 15
    NOT_IMPLEMENTED = 16
    START_PROTOCOL = 17
    AUTHENTICATION_OK_JFK_REGISTERED_HANDOFF = 18 # Final AUTH ok, JFK was registered to database. Go to handoff and/or end protocol.
    ADDITIONAL_AUTHENTICATION_FACTORS_NEEDED = 19
    SHARED_SECRETS_COMPUTED = 20
    CONNECTED = 21
    SERVICE_ADVERTISEMENT_DETECTED = 22
    INVALID_BNONCE = 23 # An invalid BNONCE is either one that failed Location Service signature, or one that could not be decrypted (bad MAC or bad secret keys).
    CONNECTION_REQUEST = 24 # Currently unused.
    BNONCE_RECEIVED = 25
    UNEXPECTED_MESSAGE_COUNTER = 26
    NO_SERVICE_ADVERTISEMENT_DETECTED = 27
    CONNECTION_ERROR = 28
    CONNECTION_CLOSED = 29
    INVALID_HEADER = 30 # Any values in the header are not those expected: SPI, message counter, message type, exchange type, etc.
    USER_KEY_NOT_FOUND = 31 # Did not find any user secret key in the database.
    AUTH_TIER2_PAYLOAD_OK = 32 # The AUTH_TIER2 payload is ok. Proceed to next state (typically TIER2_PRIVACY_AUTHENTICATION_ADDITIONAL_AUTHENTICATION_FACTORS).
    MINIMUM_FACTOR_SCORE_FULFILLED = 33 # The minimum required number of authentication factors (score) has been reached.
    NO_MORE_AUTHENTICATION_FACTORS = 34 # There are no more authentication factors to send, from the user to the Location Service. Authentication has to fail.
    AUTHENTICATION_OK_JFK_NOT_REGISTERED_HANDOFF = 35 # Final AUTH ok. JFK was not registered, either because the agent opted not to do it, or because the registration failed (existing, equal key?). Go to handoff and/or end protocol, or handle JFK non-registration.
    HANDED_OFF = 36 # Communications proceed with RP.
    CONNECTION_REQUEST_ACCEPTED_CONNECTED = 37 # The connection request was accepted by the Location Service and both peers are now connected.
    SERVICE_ADVERTISEMENT_SENT = 38 # The Bluetooth (or another medium) service advertisement is sent (or broadcast, depending on the technology).