# -*- coding: utf-8 -*-
"""
Created on Wed May  6 19:07:52 2015

@author: locksmith
"""
#from enum import IntEnum, unique
#from charm.core.engine.util import objectToBytes, bytesToObject

# Defines constants for all modules.
AES_BLOCK_SIZE_BYTES = 16 # The block size, in bytes, for AES. It is used, e.g., to compute the estimated encrypted payload (through PKCS7 padding) in LOCATHE.
CHARM_AUTHENTICATEDCRYPTOABSTRACTION_FIXED_OVERHEAD_BYTES = 194 # The fixed overhead added by Charm symcrypto.py AuthenticatedCryptoAbstraction. Used to compute an estimate of encrypted payload.
DEFAULT_PAIRING_GROUP = 'SS512'     # PaingGroup name with which ABE keys are to be created.

# Key types. The text descriptions are directly extracted from the keyType table in the databse.
ABE_AUTHORITY_SECRET_KEY_TYPE = "ABE Authority Secret Key" # String text that identifies the key type for ABE authority secret key.
ABE_AUTHORITY_PUBLIC_KEY_TYPE = "ABE Authority Public Key" # String text that identifies the key type for ABE authority public key.
ABE_USER_SECRET_KEY_TYPE = "ABE User Secret Key" # String text that identifies they key type for ABE user secret key.
PASSWORD_HASH_KEY_TYPE = "Password Hash (KDF)" # String text that identifies the key type.
LOCATHE_JOINT_FACTOR_KEY_KEY_TYPE = "LOCATHE Joint Factor Key" # The old longTermShared key, now Joint Factor Key, computed at the Handoff stage of LOCATHE.
SHARED_KEY_KEY_TYPE = "Shared Key" # A generic secret shared key.
TOTP_SEED_LOCATHE_KEY_TYPE = "TOTP Seed LOCATHE" # The seed for the TOTP computation engine, used by LOCATHE in-band TOTP authentication.
TOTP_SEED_OOB_KEY_TYPE = "TOTP Seed Out-Of-Band" # The seed for TOTP computation engine, exclusively for TOTP values provided out-of-band (e.g., typed by the user), not the one computed by the LOCATHE protocol.
PKI_SECRET_KEY_TYPE = "PKI Secret Key" # The secret value of the public/secret key pair in PKI.
FINGERPRINT_KEY_TYPE = "Fingerprint" # A value that represents, or simulates, a fingerprint template/minutiae.
FACE_KEY_TYPE =  'Face' # A value that represents, or simulates, a facial pattern for facial recognition.
IRIS_KEY_TYPE = 'Iris' # A value that represents, or simulates, iris template for iris recognition.
PIN_KEY_TYPE = 'PIN' # A PIN value, typically numeric.
PATTERN_KEY_TYPE = 'Pattern' # A value that represents a pattern a user draws on a screen (typically in smartphones).

#LOCAUTH_UUID = "1e0ca4ea-299d-4335-93eb-27fcfe7fFEFF"  # UUID of the server service.
LOCAUTH_UUID = "10caa7h0-5e12-71ce-010c-a7hebeac0140" # UUID of the Location Service. An attempt to write "locauth-service-locathebeacon" in hexspeak (with 0s for filling in).
LOCAUTH_BLUETOOTH_SERVICE_DESCRIPTION = "LOCAUTH Service" # Description of the Bluetooth service.
BLUETOOTH_RECEIVE_BUFFER_SIZE = 1024 # Length of Bluetooth receive buffer.
INET_RECEIVE_BUFFER_SIZE = 4096 # Receive buffer size for receiving messages
DIGEST_DEFAULT = "sha256" # Default message digest calculation algorithm.
LOCATION_SERVICE_CERTFILE = "locationService.crt" # Filename for Location Service X.509 certificate.
LOCATION_SERVICE_KEYFILE = "locationService.key"  # Filename for Location Service ABE secret keys.

LOCATION_SERVICE_AUTHORITY_DATABASE = 'locationserviceauthority.db' # Filename for an authority agent database.
LOCATION_SERVICE_DATABASE = "locationservice.db" # Filename for the Location Service database.
LOCATION_SERVICE_USER_DATABASE = "locationserviceuser.db" # Filename for the user agent database.

LOCATION_SERVICE_AUTHORITY_DATABASE_TEST = 'locationserviceauthoritytest.db' # Filename for a test authority agent database.
LOCATION_SERVICE_DATABASE_TEST = "locationservicetest.db" # Filename for a test Location Service database.
LOCATION_SERVICE_USER_DATABASE_TEST = "locationserviceusertest.db" # Filename for a test user agent database.

SYMMETRIC_KEY_LENGTH_BITS = 256 # Length in bits of a typical symmetric secret key.
AUTH_PRFPLUS_KEY_LENGTH_BITS = 1024 # Length in bits of the prf+ output for AUTH payload computation. This output servers as a key for an outer prf.
KPWD_LENGTH_BITS = 256 # Length of the Kpwd value computed within LOCATHE, which will serve as key to compute the ENONCE value.
LSK_LENGTH_BITS = 256 # Length of secret LSK key in bits. The length of the public LPK key derives from EC arithmetic with the global parameter g.
RANDOM_SECRET_LENGTH_BITS = 256 # length in bits for a random secret. Use multiples of 8.
BNONCE_LENGTH_BITS = 256 # length in bits for the BNONCE plaintext (the actual token before encryption, or Nb. Why didn't I name this NB_LENGTH_BITS?).
RSA_KEY_LENGTH = 3072 # Length in bits for an RSA key.
DEFAULT_ATTRIBUTE_EXPIRATION_SECONDS = 1*365*24*60*60 # Default expiration time, in seconds, for an attribute (1 year).
DEFAULT_KEY_EXPIRATION_SECONDS = 1*365*24*60*60 # Default expiration time, in seconds, for a secret key (1 year).
DEFAULT_ABE_AUTHORITY_KEY_EXPIRATION_SECONDS = 1*365*24*60*60 # Default expiration time, in seconds, for an authority (ABE) key (1 year).
DEFAULT_ABE_USER_KEY_EXPIRATION_SECONDS = 1*365*24*60*60 # Default expiration time, in seconds, for a user (ABE) key (1 year).
DEFAULT_JOINT_FACTOR_KEY_SECRET_SECONDS = 60*60 # Default expiration time, in seconds, for a joint factor key (old long term secret within LOCATHE protocol) (one hour).
DEFAULT_BROADCAST_EXPIRATION_SECONDS = 10 # Default broadcast validity duration, in seconds, within LOCATHE protocol (10 minutes).
PBKDF2_HASH_LENGTH_BYTES = 32 # Default length, in bits, for a PBKDF2 hash.
PBKDF2_COUNT = 4096 # Default number of rounds for a PBKDF2 generation.
GLOBAL_MINIMUM_FACTOR_SCORE = 14 # Default global minimum factorScore of authentication factors necessarity to authenticate a user at Tier 2 level. A user-specific factorScore can be implemented in the future.

TOTP_SEED_LENGTH_BITS = 256 # Length in bits of a typical TOTP seed.
TOTP_TOKEN_LENGTH_DIGITS = 12 # Length in digits of a default TOTP token.
TOTP_VALIDITY_INTERVAL_SECONDS = 30 # Time interval of validity for a TOTP token, in seconds.

ENTITY_TYPE_AUTHORITY_RP = "Authority-RP"
ENTITY_TYPE_USER = "User"
ENTITY_TYPE_LOCATION_SERVICE = "Location Service"
ENTITY_ID_LOCATION_SERVICE = "location.service"
ENTITY_ID_TIER1_ANONYMOUS_USER = "tier1.anonymous.user"

CHARM_CRYPTO_DECENTRALIZED_ABE_GID_KEY = 'gid' # Identifier, or index string, or key, that identifies a 'gid' in the D-ABE module.

# The public g or group generator for Multi-authority ABE (dabe_aw11). Can only represent here as JSON serialized object.
# as pairing.Element: {'g': [4647410966685747155997615907154229121528527324754269663336195599353237223002331443812207901487306690861432752340739340809605331107821364450292779623805311, 2232316172744932151046333176920403893157461470967360430806431709284199821153911535922929021696334599999597958533298815329195667999543697176342003459716938]
GLOBAL_GROUP_GENERATOR_JSON = """{"g": {"__value__": "1:WLwSVT5DRp/sclwycXkKPmVjvTzcE4nrHSfOkezqP2EfaWZhbhdeOGJULG72rRmKcJh8TBr/DGU1ewXwMrZxfwA=", "__pairingCurve__": "SS512", "__class__": "pairing.Element"}, "__pairingCurve__": "SS512"}"""

DEFAULT_DESTINATION_TCP_PORT = 48880 # Default TCP port, from a Location Service to which a user agent should connect.
DEFAULT_SOURCE_TCP_PORT = 48880 # Default TCP port to which a Location Service server will listen for connections (both destination and source are actually the same here).

# LOCATHE message field/key names.
HEADER_FIELD_NAME = 'header'
HEADER_FIELD_NAME_SPI_I = 'spii' # 8 bytes.
HEADER_FIELD_NAME_SPI_R = 'spir' # 8 bytes.
HEADER_FIELD_NAME_EXCHANGE_TYPE = 'exchange_type' # 1 bytes.
HEADER_FIELD_NAME_MESSAGE_TYPE = 'message_type' # Flag (1 bit).
HEADER_FIELD_NAME_SENDER_TYPE = 'sender' # Flag (1 bit).
HEADER_FIELD_NAME_MESSAGE_COUNTER = 'counter' # 4 bytes.
HEADER_FIELD_NAME_MESSAGE_LENGTH = 'length' # 4 bytes.

PAYLOAD_FIELD_NAME_KER = 'ker'
PAYLOAD_FIELD_NAME_KER_SIGNATURE = 'kerSignature' # Proposed modification for a (half) authenticated ECDHE in Broadcast phase. \
                                                  # User agent will refuse KEr if not properly signed by Responder, mitigating MitM 
                                                  # impersonating Responder at this phase.
PAYLOAD_FIELD_NAME_KEI = 'kei'
PAYLOAD_FIELD_NAME_UUID = 'uuid'
PAYLOAD_FIELD_NAME_SERVICE_DESCRIPTION = 'service'
PAYLOAD_FIELD_NAME_NI = 'ni'
PAYLOAD_FIELD_NAME_NR = 'nr'
PAYLOAD_FIELD_NAME_BNONCE = 'bnonce'
PAYLOAD_FIELD_NAME_BNONCE_SIGNATURE = 'bnonceSignature'
PAYLOAD_FIELD_NAME_LOCATION_SERVICE_CERTIFICATE = 'locationServiceCertificate'
PAYLOAD_FIELD_NAME_AUTH_TIER1_I = 'authTier1i'
PAYLOAD_FIELD_NAME_AUTH_TIER1_R = 'authTier1r'
PAYLOAD_FIELD_NAME_AUTH_TIER1_R_SIGNATURE = 'authTier1rSignature'
PAYLOAD_FIELD_NAME_AUTH_TIER2_I = 'authTier2i'
PAYLOAD_FIELD_NAME_AUTH_TIER2_R = 'authTier2r'
PAYLOAD_FIELD_NAME_AUTH_TIER2_R_SIGNATURE = 'authTier2rSignature'
PAYLOAD_FIELD_NAME_ENONCE = 'enonce'
PAYLOAD_FIELD_NAME_ID_I = 'idi'
PAYLOAD_FIELD_NAME_ID_R = 'idr'
PAYLOAD_FIELD_NAME_AUTH_I = 'authi'
PAYLOAD_FIELD_NAME_AUTH_R = 'authr'
PAYLOAD_FIELD_NAME_RAW_MESSAGE = 'rawMessage'
PAYLOAD_FIELD_NAME_LPKI = 'lpki'
PAYLOAD_FIELD_NAME_LPKR = 'lpkr'
PAYLOAD_FIELD_NAME_AUTHENTICATION_KEY_TYPE = 'authenticationKeyType' # The keyType the user chose to compute the ENONCE challenge (or another challenge?).
PAYLOAD_FIELD_NAME_CURRENT_FACTOR_SCORE = 'currentFactorScore' # The accummulated factorScore of all authentication factors sent by the Initiator/user agent.
PAYLOAD_FIELD_NAME_MINIMUM_FACTOR_SCORE = 'minimumFactorScore' # The mininum required factor score by the Location Service to authenticate the user.

# LOCATHE constants/types values.
HEADER_EXCHANGE_TYPE_BROADCAST_ECDHE_BLUETOOTH_ADVERTISEMENT = b'a'
HEADER_EXCHANGE_TYPE_BROADCAST_ECDHE_BROADCAST_BNONCE = b'b'
HEADER_EXCHANGE_TYPE_SEND_KE_K = b'k'
HEADER_EXCHANGE_TYPE_AUTH1 = b'1'
HEADER_EXCHANGE_TYPE_AUTH2 = b'2'
HEADER_EXCHANGE_TYPE_JFK_HANDOFF = b'h'

HEADER_MESSAGE_TYPE_RESPONSE = True # Here we follow IKEv2 convention for flag values.
HEADER_MESSAGE_TYPE_BITMASK = 0b00100000
HEADER_MESSAGE_TYPE_REQUEST = False
HEADER_SENDER_TYPE_BITMASK = 0b00001000
HEADER_SENDER_TYPE_INITIATOR = True
HEADER_SENDER_TYPE_RESPONDER = False
HEADER_FIELD_FLAGS_RESET_UNUSED_MASK = 0b00101000

MESSAGE_LENGTH_FIELD_LENGTH_BYTES = 4 # This is the length of the message field length in bytes.
SPI_LENGTH_BYTES = 8 # Length of the SPIr and SPIi (Security Parameter Index) values/fields in bytes.
HEADER_STRUCT_FORMAT = ">I8s8sccccI" # The struct format of the LOCATHE message header, as below.

# Agent types such that the agent objects can identify themselves to other objects/functions if needed.
LOCATHE_USER_AGENT_TYPE = 'user.agent'
LOCATHE_LOCATION_SERVICE_AGENT_TYPE = 'location.service.agent'

# Key names (for dicts) for messages and payloads to be saved to later compute <SignedOctets>.
#MESSAGE_RECEIVED_TO_AUTHENTICATE = "MessageReceivedToAuthenticate"
#MESSAGE_SENT_TO_AUTHENTICATE = "MessageSentToAuthenticate"
SIGNED_OCTETS_KEI_NI_RAW_MESSAGE = "signedOctetsKeiNiRawMessage"
SIGNED_OCTETS_KER_NR_RAW_MESSAGE = "signedOctetsKerNrRawMessage"
SIGNED_OCTETS_IDR_PAYLOAD = "signedOctetsIdrPayload"
SIGNED_OCTETS_IDI_PAYLOAD_TIER1 = "signedOctetsIdiPayloadTier1" # See ENTITY_ID_TIER1_ANONYMOUS_USER = "tier1.anonymous.user". It is an anonymous dummy user.
SIGNED_OCTETS_IDI_PAYLOAD_TIER2 = "signedOctetsIdiPayloadTier2" # Here, the real userID of the user must be utilized.

# LOCATHE prf literal strings..
LOCATHE_TIER1_AUTH_LITERAL_STRING = b'LOCATHE Tier_1 Authentication' # A literal string that complements the value in the inner prf+ that results in the key for the prf in AUTH_TIER_1.
LOCATHE_TIER2_AUTH_LITERAL_STRING = b'LOCATHE Tier_2 Authentication' # A literal string that complements the value in the inner prf+ that results in the key for the prf in AUTH_TIER_2.
LOCATHE_TIER2_SPWD_LITERAL_STRING = b'LOCATHE Tier_2 Spwd' # Literal string complement for prf in Tier_2, Spwd generation.
LOCATHE_JOINT_FACTOR_KEY_LITERAL_STRING = b'LOCATHE Joint Factor Key' # Literal string complement for prf in Handoff stage.

"""
Tentatively, the LOCATHE header, adapted from IKEv2, is:

                    1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Length (4 octets)                       |  unsigned int
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Initiator's SPIi                        |  8 char
|                           (8 octets)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Responder's SPIr                        |  8 char
|                           (8 octets)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Flags (1 octet)| Exchange Type | MjVer | MnVer | Next Payload  |  char | char | char (both fields) | char
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Message Counter (4 octets)                  |  unsigned int
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

MjVer, MnVer, Next Payload are currently unused.
    
The messageType and sender are coded within the Flags field, tentatively as so:

Flags (1 octet) - Indicates specific options that are set for the
message.  Presence of options is indicated by the appropriate bit
in the flags field being set.  The bits are as follows:

    +-+-+-+-+-+-+-+-+
    |X|X|R|X|I|X|X|X|
    +-+-+-+-+-+-+-+-+

Where:

*  R (Response) - This bit indicates that this message is a
     response to a message containing the same Message counter.  This bit
     MUST be cleared in all request messages and MUST be set in all
     responses.

*  I (Initiator) - This bit MUST be set in messages sent by the
     original initiator of the message and MUST be cleared in
     messages sent by the original responder.  It is used by the
     recipient to determine which 8 octets of the SPI were generated
     by the recipient.

*  X - unused.
"""

