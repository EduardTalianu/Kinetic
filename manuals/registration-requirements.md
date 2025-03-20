# KCM Client Registration Requirements

## Overview
This document provides the requirements for implementing client registration and key exchange in KCM agents.

## Required Components

### 1. Client Information Collection
- **REQUIRED**: Function to gather basic system information:
  - Hostname
  - Username
  - Operating system version
  - Machine identifier (GUID, serial number, etc.)
  - MAC address (when available)

### 2. RSA Public Key Handling
- **REQUIRED**: Ability to parse and import the server's RSA public key
- **REQUIRED**: Implementation of RSA-OAEP encryption with SHA-256

### 3. AES Key Generation
- **REQUIRED**: Function to generate secure random 256-bit AES keys
- **REQUIRED**: Implementation of AES-CBC mode encryption and decryption
- **REQUIRED**: Proper PKCS#7 padding implementation

### 4. HTTP Communication
- **REQUIRED**: Ability to send HTTP POST requests with JSON payloads
- **REQUIRED**: Ability to parse JSON responses
- **REQUIRED**: Base64 encoding/decoding capability

### 5. Client ID Management
- **REQUIRED**: Storage of server-assigned client ID
- **REQUIRED**: Persistence of client ID across restarts

### 6. Error Handling
- **REQUIRED**: Retry mechanism for failed registration attempts
- **REQUIRED**: Exponential backoff for connection failures
- **REQUIRED**: Logging of registration process steps and errors

## Protocol Implementation Requirements

### First Contact Phase
- **REQUIRED**: Send minimal system information to any valid server path
- **REQUIRED**: Set first contact flag in request
- **REQUIRED**: Process and store server-assigned client ID
- **REQUIRED**: Extract and import server's RSA public key

### Key Exchange Phase
- **REQUIRED**: Generate a secure random AES-256 key
- **REQUIRED**: Encrypt the key using server's RSA public key
- **REQUIRED**: Send the encrypted key to dedicated registration endpoint
- **REQUIRED**: Include a random nonce for replay protection
- **REQUIRED**: Verify server response for success confirmation

### Secure Communication Phase
- **REQUIRED**: Encrypt all subsequent communications with the client's AES key
- **REQUIRED**: Include required operation type and payload in encrypted data
- **REQUIRED**: Properly decrypt server responses
- **REQUIRED**: Handle command processing in encrypted channel

## Testing Requirements

- **REQUIRED**: Verify successful registration with test server
- **REQUIRED**: Confirm encrypted communications work correctly
- **REQUIRED**: Validate key rotation handling
- **REQUIRED**: Test error cases and recovery

## Security Requirements

- **REQUIRED**: No hard-coded cryptographic keys
- **REQUIRED**: Secure storage of client keys
- **REQUIRED**: Use of secure random number generators
- **REQUIRED**: Proper encryption padding
- **REQUIRED**: Protection against key extraction



# client_registration_protocol.txt

KCM C2 Client Registration Protocol v1.0
=======================================

Overview:
---------
This document defines the standard protocol for client registration and key exchange 
in the Kinetic Compliance Matrix C2 framework.

Registration Flow:
-----------------
1. First Contact (Client → Server)
   - HTTP POST to any valid path in path pool
   - Minimal JSON payload: { "d": <json-system-info>, "t": <random-padding>, "f": true }
   - System info should include at minimum: { "Hostname", "IP", "Username", "OsVersion" }

2. Server Response to First Contact
   - JSON response: { "pubkey": <rsa-public-key>, "c": <client-id>, "f": true, "r": <rotation-info> }
   - Client stores the assigned client_id

3. Key Registration (Client → Server)
   - HTTP POST to "/client/service/registration"
   - JSON payload: { "encrypted_key": <base64-encrypted-aes-key>, "client_id": <client-id>, "nonce": <random-nonce> }
   - The client-generated AES-256 key is encrypted with server's RSA public key

4. Server Acknowledgment
   - JSON response: { "status": "success", "message": "Key registration successful", "nonce": <echoed-nonce> }

5. Standard Beacons (Client → Server)
   - HTTP POST to any valid path
   - JSON payload encrypted with client's AES key: { "d": <encrypted-data>, "t": <random-padding> }
   - Encrypted data contains: { "op_type": "beacon", "payload": <system-info> }

Protocol Requirements:
--------------------
- All clients MUST implement the complete protocol
- All encryption MUST use standardized algorithms (RSA-OAEP for key exchange, AES-CBC for data)
- All JSON fields MUST use the abbreviated field names as specified
- All timestamps MUST use "YYYY-MM-DD HH:MM:SS" format
