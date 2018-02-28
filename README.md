# AuthenticationService

## Authentication Service proof-of-concept (PoC) system for Ph.D. dissertation.

This Proof-of-Concept implements:

- The Location Service (LocAuth) and its key functionalities.
- Databases to store Location Service data, such as entities, keys, key types, etc. The system includes three databases:
  - one for Location Service;
  - one for ABE Authorities (Relying Parties, RPs);
  - and one for users.
  All databases have the same construction, but might contain different data.
- The LOCATHE location-enabled authentication protocol in the form of two agents that run the protocol on behalf of entities.
  - The Location Service agent, which is also named Service or Responder (r).
  - The User agent, also named the Initiator (i).
  
## Directories

`AuthenticationService/authenticationservice/.` contains the modules for the Location Service and database management.

`AuthenticationService/authenticationservice/test` contains unit test files, the protocol simulator (locathesimulator.py) and agent simulators (locationserviceagentsimulator.py, useragentsimulator.py). We will probably transfer these protocol-specific files to the parent directory here, as they are more simulators than test files.

`AuthenticationService/authenticationservice/networkTest` has a few network-specific test modules.

`AuthenticationService/authenticationservice/timingattackresilience` has legacy experiments with modfications to Charm to mitigate timing attacks in ABE encryption/decryption. The initiative has been abandoned.

## Running the PoC

For a vizualization of the LOCATHE protocol at work, run `locathesimulator.py`. This code will instantiate the peer agent objects, the appropriate Location Service, Authentication, User objects, will populate the databases with necessary data for the simulation and start both Location Service and User agent peers in their own independent processes within the same localhost.

The agents will then engage into the LOCATHE exchange and complete the protocol, either successfully or not, depending on the options that were chosen for the simulation (to either forcefully fail or not).

## Unit Tests

The majority of modules are unit tested,  and the tests are under `AuthenticationService/authenticationservice/test`. Functions in the LOCATHE simulator/agents are mostly integration tested due to the necessity of network communications with the other peer.
