# Nextcloud end-to-end encryption

## Abstract
This document specifies the end-to-end encryption protocol used by Nextcloud clients.
It defines how clients manage key material, how the content and the metadata of end-to-end encrypted folders are encrypted, signed and stored on a Nextcloud server,
and how encrypted folders are shared with other users and with users without a Nextcloud account.

## Status of this document
This document specifies version 2.1 of the Nextcloud end-to-end encryption protocol, using the metadata versions `"2.0"` and `"2.1"`.
It is the authoritative implementation guideline for Nextcloud clients.

The previous version of this protocol is specified in [RFC_v1.md](./RFC_v1.md).
The change history is listed in the [README](./README.md#history).

We would like to invite you to scrutinize our source code and cryptographic approach.
We are looking forward to your input to refine our approach towards client-side encryption.
In addition, we will also make sure to validate our approach on time by external cryptographic experts.

## Table of contents

* [Abstract](#abstract)
* [Status of this document](#status-of-this-document)
* [Introduction](#introduction)
  * [Design goals](#design-goals)
  * [Scope](#scope)
* [Conventions and terminology](#conventions-and-terminology)
  * [Requirements language](#requirements-language)
  * [Terminology](#terminology)
* [Architecture overview](#architecture-overview)
  * [Trust model](#trust-model)
  * [Key hierarchy](#key-hierarchy)
  * [Folder structure](#folder-structure)
* [Threat model and security goals](#threat-model-and-security-goals)
  * [Attacker model](#attacker-model)
  * [Security goals](#security-goals)
* [Data formats](#data-formats)
  * [Metadata file](#metadata-file)
  * [Initial metadata](#initial-metadata)
* [Cryptographic operations](#cryptographic-operations)
  * [Signing the metadata](#signing-the-metadata)
  * [Verifying the metadata](#verifying-the-metadata)
* [Protocol procedures](#protocol-procedures)
  * [Adding an end-to-end encrypted device](#adding-an-end-to-end-encrypted-device)
  * [Creating an end-to-end encrypted folder](#creating-an-end-to-end-encrypted-folder)
  * [Modifying content of an end-to-end encrypted folder](#modifying-content-of-an-end-to-end-encrypted-folder)
  * [Accessing content of an end-to-end encrypted folder](#accessing-content-of-an-end-to-end-encrypted-folder)
  * [Migrating filedrop](#migrating-filedrop)
  * [Sharing encrypted folders to other users](#sharing-encrypted-folders-to-other-users)
  * [Sharing to external users](#sharing-to-external-users)
* [HTTP API](#http-api)
* [Security considerations](#security-considerations)
  * [Accepted risks](#accepted-risks)
  * [Attack scenarios](#attack-scenarios)
  * [Handling of complete key material loss](#handling-of-complete-key-material-loss)
* [Versioning and backward compatibility](#versioning-and-backward-compatibility)
* [Appendix: Possible extensions](#appendix-possible-extensions)

## Introduction
Existing client-side encryption solutions often prevent the sharing of encrypted files or the usage on multiple devices.
The Nextcloud end-to-end encryption is designed to allow both, while the server, which stores the encrypted data, is not able to access the content.

The encryption is based upon an asymmetric cryptographic system.
Every user owns a key pair, the certificate of the public key is issued by the Nextcloud server.
Content and metadata of encrypted folders are encrypted with symmetric keys, which are encrypted for every user with access to the folder.

### Design goals
_This section is informative._

The end-to-end encryption has to fulfill the following business and technical criteria.

#### Usage of widely available and tested libraries for crypto primitives
We believe that for security-sensitive functionalities relying on existing and proven libraries is an essential requirement.
Thus we require that:

* The used library for cryptographic primitives is in use widely.
* The used library for cryptographic primitives has undergone successful security audits.

Also due to our wide range of supported systems, the library has to be available for all currently supported versions of the following environments:

* iOS
* Android
* macOS
* Windows
* commonly used Linux distributions
* Web browsers (e.g. using the Web Crypto API)
* PHP

While we do not have any current plans to add support for potential server-side decryption we want to keep this possibility open for the future.

#### Sharing functionality
The Nextcloud end-to-end encryption has to offer support for the following sharing scenarios:

* Sharing encrypted folders with other users
* Any user that is part of the shared folder is able to add new users to the share
* Sharing encrypted folders with users without a Nextcloud account using public shares

#### Optional central data recovery
While end-to-end encryption is meant to prevent access to data for other parties the reality is: People may lose their encryption keys.

While in a home user environment this might be acceptable, in an enterprise this can have grave implications.
Thus an optional central data recovery has to be available offering the following capabilities:

* Central recovery key per instance can be generated
* Central recovery key is not stored on the instance and can be safely exported (e.g. to be stored in a physical vault)
* All data will also be encrypted with the central recovery key when enabled
* Users are prominently warned in the UI of their clients if a central data recovery key is enabled
* When a central data recovery key is enabled the existing end-to-end encrypted folders are not affected

#### Simple multi-device management
Access to encrypted data should easily be possible from any device the end-user owns, this includes all mobile devices as well as desktop devices.

Thus:
* Sharing keys between existing devices has to be frictionless
* Newly added devices should have access to all previously encrypted data

#### Simple authenticated key exchange
Key exchange is a key problem of any cryptographic system.
On one hand one wants to ensure that the key of the participating parties is authentic.
On the other hand, manual comparison of key material is cumbersome and rarely something that regular users can be bothered to do.

A secure and yet simple system has to implement the following properties:
* Key exchange between parties should be frictionless
* Optionally, clients can offer key verification by comparing certificate fingerprints (e.g. by using QR-Codes)

#### Support for HSM
To fulfill enterprise security requirements it should be possible that key material is generated by a hardware security module.
Thus offering strong authentication, tampering resistance and a complete audit trail.

#### Versioning
The protocol has to support versioning in case of future changes in the metadata or cryptographic parameters.

### Scope
_This section is informative._

The following sharing scenarios are out of scope:

* Sharing single files or folders from an encrypted folder
* Sharing encrypted folders with whole groups
* Sharing subfolders of encrypted folders, it is only possible to share the topmost encrypted folder

Since the data is not accessible to the server and to simplify the implementation, losing the following features is accepted:

* Server-side trash bin
* Server-side versioning
* Server-side search
* Server-side previews
* Sharing to groups
* Sharing at the level of individual files
* Sharing of subfolders of an encrypted folder
* Scanning with files_antivirus. Metadata are also ignored by files_antivirus, even though they could be scanned, it adds too much latency.
* Integrity of filedrop entries, see [Accepted risks](#accepted-risks)

## Conventions and terminology

### Requirements language
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals, as shown here.

Sections marked as informative do not contain requirements.

### Terminology
* client: an application implementing this protocol, e.g. the desktop, mobile or web client.
* device: anything able to run one of our supported clients.
* server: the Nextcloud server with the `end_to_end_encryption` app enabled.
* topmost encrypted folder: an encrypted folder whose parent folder is not encrypted.
* subfolder: an encrypted folder inside of a topmost encrypted folder.
* random identifier: the name of an encrypted file or subfolder on the server, used instead of its cleartext name.
* file-metadata: cleartext name, mimetype, file-key, nonce/iv and authTag of a file
* file-key: the actual key used to encrypt the file
* folders-array: associative array mapping random identifiers to folder names
* files-array: associative array mapping random identifiers to the metadata of the file
* users-array: array of information of users. Used to list all users of a shared and encrypted folder, with their certificate and the encrypted metadata-key
* metadata-key: key used to encrypt the metadata of the folder
* filedrop-key: key used to encrypt a single entry of the filedrop array
* metadata: metadata of all files (file-metadata) and sub-folders in the encrypted folder, list of checksums of metadata-keys and a counter
* counter: a number in the metadata that is increased with every change of the metadata
* lock token: a token issued by the server when locking an encrypted folder, required for all modifications of the folder
* share user: the pseudo user representing the recipients of a public share
* PEM: Textual encoding of certificate and key structures according to [RFC 7468](https://datatracker.ietf.org/doc/html/rfc7468)

## Architecture overview
_This section is informative._

### Trust model
As a PKI approach for encryption is used, every certificate is issued by a central root authority.
By default, the Nextcloud server acts as a root authority and issues the certificates from certificate signing requests (CSR) of the clients.
Alternatively, an external certificate authority may be used with certificates being generated and their lifetime tracked outside of the `end_to_end_encryption` Nextcloud app.
That would be the case if certificates (and their associated key-pair) are stored on dedicated USB tokens.

The server is trusted when requesting the server certificate, when adding a new device of a user, and when a certificate of another user is downloaded for the first time (trust on first use, TOFU).

### Key hierarchy
* Every user owns an RSA key pair. The certificate is stored on the server, the private key is stored on the server encrypted with a key derived from a mnemonic only known to the user.
* Every topmost encrypted folder has a metadata-key, which is encrypted with the public key of every user with access to the folder.
  All subfolders of a topmost encrypted folder share its metadata-key.
* Every file has its own file-key, which is stored in the encrypted metadata of its folder.
* Every filedrop entry has its own filedrop-key, which is encrypted with the public key of every user with access to the folder.

### Folder structure
Data access to encrypted folders happens via the regular WebDAV API.
On the server, encrypted files and subfolders are stored using random identifiers as names.
Every encrypted folder has a metadata file, which maps the random identifiers to the cleartext names and contains the file-keys of the files.

## Threat model and security goals

### Attacker model
The end-to-end encryption MUST protect against an attacker with the following capabilities:

* Attacker can circumvent underlying TLS/SSL transport encryption
* Attacker has full control over the server (e.g. compromised server or malicious admin)
* Attacker cannot tamper with key exchange between clients and with initial connection of a new client to a share (Trust on first use (TOFU))
  * Future support for separate trusted key server could avoid the TOFU compromise and therefore protect against a stronger attacker.
* Removed users: A user who is part of a shared end-to-end encrypted folder is trusted until the user has been removed

### Security goals
The protocol MUST achieve the following goals when assuming an attacker as specified above.

* Access to ciphertext MUST NOT leak file content nor file names nor the names of subfolders.
  The accepted risks are listed in [Accepted risks](#accepted-risks).
* Once a user has been removed from an encrypted folder they SHOULD have no relevant key material to decrypt files updated or created in the future.
* **Confidentiality**: No one, except the legitimate recipients, has access to the encrypted documents.
* **Integrity**: Even with writable access to the ciphertext one is not able to tamper with the data unnoticed.
* **Authentication**: All valid changes (uploading new files, changing existing files, removing existing files) to an end-to-end encrypted folder are only made by a user who is part of the (shared) folder.
  Malicious changes are detected at the latest when the client that made the most recent valid change synchronizes the next time.

## Data formats

### Metadata file
Every encrypted folder MUST have a metadata file containing the following information:

* metadata of all files (file-metadata) and sub-folders
* list of checksums of metadata-keys
* users array
* counter

The metadata is a JSON document with the following structure depicted below.
We use a notation with inline comments (`//`) for better readability.
Note that comments are not available in standalone JSON and only used here for better understanding.

In case the central data recovery key is enabled the metadata MUST also be encrypted towards the server's central data recovery key.
Clients MUST show a prominent warning to the users for such scenarios.

The JSON document contains at least 3 keys and at most 4 keys:
- `metadata`: The value is the encrypted inner metadata
- `users`: The list of users with access to the folder, only present for topmost encrypted folders
- `version`: The metadata version, see [Versioning and backward compatibility](#versioning-and-backward-compatibility)
- `filedrop`: (optional) file drop encrypted files

```json
{
   "metadata": {
      // The "ciphertext" key contains the encrypted metadata of the folder,
      // see "Metadata" example below for the plaintext structure.
      // It is encrypted using AES/GCM/NoPadding with 128 bit key size.
      // 1. The inner JSON document is stringified
      // 2. Then gzipped
      // 3. Then encrypted
      //    MAKE SURE to always encrypt it using the BINARY representation (NOT base64)
      //    of "encryptedMetadataKey" from the "users" array below).
      // 4. Then Base64 encoded
      "ciphertext": "encrypted metadata",
      "nonce": "123",
      "authenticationTag": "123"
   },
   "users": [
      // The following contains the reference to all users who have access to the share, including owner.
      // A newly created folder thus will also have this array with the owner as its first entry.
      // The metadata-key is encrypted with RSA/ECB/OAEPWithSHA-256AndMGF1Padding
      {
         "userId": "testUser",
         "certificate": "public key of this user",
         "encryptedMetadataKey": "encrypted metadata-key then base64, but, ALWAYS used in NON-base64 format when encrypting data with it)"
      }
   ],
   "filedrop": {
      "<uid>": {
         // The "ciphertext" key contains the encrypted metadata for the file
         // see "Filedrop" example below for the plaintext structure.
         // It is encrypted using AES/GCM/NoPadding with 128 bit key size,
         // using a newly generated filedrop-key for every entry.
         // 1. The inner JSON document is stringified
         // 2. Then gzipped
         // 3. Then encrypted
         // 4. Then Base64 encoded
         "ciphertext": "encrypted metadata",
         "nonce": "123",
         "authenticationTag": "123",
         "users": [
              // The following contains the reference to all users who have access to filedrop.
              // The filedrop-key is encrypted with RSA/ECB/OAEPWithSHA-256AndMGF1Padding
             {
               "userId": "testUser",
               "encryptedFiledropKey": "encrypted filedrop-key then base64"
             }
         ],
      },
      // ...
   },
  "version": "2.0"
}
```

Metadata:
```json
{
   "keyChecksums": [ "list of hashes of (unencrypted) metadata-keys" ], // this builds up a history of metadata keys
   "deleted": false,
   "counter": 12,
   "folders": {
      "<uid>": "cleartext name",
      "<uid>": "cleartext name 2"
   },
   "files": {
      "<uid>": {
         // Unencrypted file name
         "filename": "test.txt",
         // Mimetype. If unknown, use "application/octet-stream"
         "mimetype": "plain/text",
         // Encryption algorithm: AES/GCM/NoPadding (128 bit key size)
         "nonce": "",
         "authenticationTag": "",
         "key": "jtboLmgGR1OQf2uneqCVHpklQLlIwWL5TXAQ0keK"
      }
   }
}
```

Filedrop:
```json
{
   // Unencrypted file name
   "filename": "test.txt",
   // Mimetype. If unknown, use "application/octet-stream"
   "mimetype": "plain/text",
   // Encryption algorithm: AES/GCM/NoPadding (128 bit key size)
   "nonce": "",
   "authenticationTag": "",
   "key": "jtboLmgGR1OQf2uneqCVHpklQLlIwWL5TXAQ0keK"
}
```

Random identifiers of files and folders MUST follow `/^[0-9a-fA-F]{32}$/`.
They SHOULD be created by generating a random UUID and removing the dashes (`-`).

### Initial metadata
When creating a new folder, the client MUST create an initial metadata file with the following values:
- the counter starts with 0
- if the folder is a topmost encrypted folder
  - a new metadata-key MUST be generated
  - the users array MUST contain the current user with userId, certificate and encrypted metadata-key
- if the folder is a subfolder of an encrypted folder
  - the metadata-key of the topmost encrypted folder MUST be used, all subfolders share the metadata-key of their topmost encrypted folder
  - the users array MUST NOT be included

## Cryptographic operations

### Signing the metadata
Every metadata file MUST be signed by the user who created or changed it.
The signature is a Cryptographic Message Syntax (CMS) signed data structure, according to [RFC 5652](https://datatracker.ietf.org/doc/html/rfc5652):
- It MUST be created using the certificate of the user.
- The signed data MUST be prepared from the metadata JSON as follows:
   1. Remove the `filedrop` part
   2. Stringify the JSON without spaces and newlines (except in keys or values), with object keys sorted alphabetically
   3. Encode the JSON string with Base64
- The SignerIdentifier of the CMS container MUST identify the userId of the user who created the signature.
- It MUST include the signed attributes described in [RFC 6488](https://www.rfc-editor.org/rfc/rfc6488.html).
- It MUST be generated in detached mode, the metadata is not included in the signature as it is already stored on the server and is always retrieved with a `GET` request.

The encoded binary CMS structure is Base64 encoded and sent as the `X-NC-E2EE-SIGNATURE` HTTP header of the request creating or updating the metadata.

### Verifying the metadata
Before using a metadata file, e.g. on a folder refresh, the client MUST verify its signature.
The signature is returned as the `X-NC-E2EE-SIGNATURE` HTTP response header of the `GET` request to the `/meta-data/<folder-id>` OCS endpoint.
It is also available as the `{http://nextcloud.org/ns}e2ee-metadata-signature` WebDAV property of the folder.

To verify the signature the client MUST:
1. Prepare the signed data from the metadata as described in [Signing the metadata](#signing-the-metadata).
2. Find the user identified by the SignerIdentifier of the CMS signature in the `users` array of the topmost encrypted folder.
3. Verify the CMS signature using the certificate of this user.

After the signature was verified, the client finds its metadata-key in the `users` array and decrypts it to decrypt the metadata.

If any of the following checks fail, the client MUST refuse further sync and inform the user:
- the new counter MUST be greater than the locally stored counter
- the signature MUST be valid
- the hash of the metadata-key MUST be in keyChecksums
- no hash MUST have been removed from keyChecksums
- the certificates of all users MUST be issued by the CA

## Protocol procedures

### Adding an end-to-end encrypted device
As a first step, a device has to be added to an account.
Depending on whether an end-to-end encrypted device already has been added to an account, the device MUST either create new key material or use existing key material.

To check whether a certificate has already been issued, the client SHOULD use the `/public-key` OCS endpoint.
In addition, the client MUST download the server's public key from the `/server-key` OCS endpoint and MUST use it to verify the certificate chain in all future operations.

#### Initial device
When a device is initially added to an account the device MUST generate all relevant key material for the user account and provision it on the server:

1. The client generates a new private key and a X.509 Certificate Signing Request (CSR), following [RFC 2986](https://datatracker.ietf.org/doc/html/rfc2986).
   The `CN` of the CSR MUST be set to the currently logged-in user ID.
2. The client uploads the CSR to the server.
   1. The client encodes the CSR using PEM encoding.
   2. The client transmits the CSR as the URL-encoded `POST` parameter `csr` to the `/public-key` OCS API endpoint.
3. The server MUST only issue a certificate if the `CN` matches the current user ID.
4. The server returns the issued certificate.
5. The client MUST verify that the certificate was signed by the server, using the previously fetched public key of the server.
6. The client stores the private key and the certificate in the keychain of the device.

In a second step, the private key is stored encrypted on the server to simplify the addition of further devices:

1. The client generates a 12 word long mnemonic from the English `BIP-0039` word list. The word list contains 2048 words, thus resulting in 2048^12 possible key combinations.
2. The client encrypts the private key:
   1. Encode the private key
      - Using [PKCS#8 (RFC 5208)](https://tools.ietf.org/html/rfc5208#section-5) and PEM encoding
      - Use Base64 to encode the resulting PEM
   2. Generate the encryption key using a key derivation function (KDF) on the generated mnemonic
      - KDF: PBKDF2 with HMAC-SHA256
      - Iterations: 600000
      - Salt: 40 randomly generated bytes
   3. Encrypt the encoded private key using the encryption key
      - AES/GCM/NoPadding
      - 256 bit key size
      - 96 bit nonce
      - 128 bit authenticationTag, which is appended to the encrypted private key
3. The client uploads the encrypted private key (including the authenticationTag), nonce and salt to the server:
   1. key, salt, and nonce are Base64 encoded
   2. Then concatenated using `|` as the separator (`{base64(key + authenticationTag)}|{base64(nonce)}|{base64(salt)}`)
   3. This string is sent as the URL-encoded `POST` parameter `privateKey` to the `/private-key` OCS endpoint.
4. The client displays the mnemonic to the user as a space-separated text and asks the user to note it down in a secure place.
   For encrypting and decrypting, the mnemonic MUST have no whitespace and MUST be lowercase.
5. The client stores the mnemonic in the keychain of the device with spaces so it can be shown more readable.

In case a user loses their device, they can recover by using the mnemonic passphrase.
The client MAY show the mnemonic passphrase in the client settings in case the user forgets their mnemonic.
On mobile devices, displaying the mnemonic MUST require the user to enter their PIN/fingerprint again.

#### Initial device with hardware USB token storage of certificate
When a device is initially added to an account the device MUST upload the relevant key material for the user account to the server:

1. The client discovers the certificate (and key pair) to use on the secure storage.
2. The client uploads the certificate to the server using the `/public-key` OCS endpoint.
3. The client MAY check the certificate of the server by using `GET` on the `/server-key` OCS endpoint.
4. The client stores the certificate ID and enables the end-to-end encryption feature on the client.

#### Further devices
In case a certificate already exists for the user the client MUST download the existing private key:

1. The client downloads the private key from the `/private-key` OCS endpoint.
2. The client asks the user for the mnemonic and decrypts the private key using AES/GCM/NoPadding as cipher (256 bit key size) and PBKDF2WithHmacSHA256 as key derivation with 600000 iterations.
   If the private key was uploaded with an older version of this protocol, the client MUST use the legacy parameters described in [Versioning and backward compatibility](#versioning-and-backward-compatibility).
3. The client MUST check that the private key belongs to the previously downloaded certificate.
4. The client MUST check that the certificate was signed by the server, using the server's public key from the `/server-key` OCS endpoint.
5. The client stores the private key in the keychain of the device.
6. The client stores the mnemonic in the keychain of the device, it SHOULD be stored with spaces so it can be shown more readable.

#### Updating a user certificate
A user certificate may expire or be revoked and renewed if needed.
In such case, a migration is needed as the key pair changes and metadata-keys encrypted with the former public key are no longer accessible.

The certificate migration is initiated by one client of the concerned user.
During the migration the following steps MUST be performed:

- All currently encrypted folders MUST be synced by the client that performs the certificate change or renewal before the migration is performed.
  The user interface of clients SHOULD block until this is done.
- The client replaces the certificate that is currently stored on the server.
- The client identifies all folders accessible by this user and for each of them:
  - decrypts the metadata-key accessible by this user
  - encrypts it with the new public key
  - uploads the metadata file again with the new encrypted metadata-key and the new certificate (without the private key)
  - signs the metadata file with the new user certificate

On demand certificate migration MAY be used as a fallback.
For every metadata update, the client MUST follow the process described in [Update metadata file](#update-metadata-file).

### Creating an end-to-end encrypted folder
To create an end-to-end encrypted folder multiple steps have to be performed.
Data access to such folders happens via the regular WebDAV API available at `/remote.php/dav/{userId}/files`.

#### Mark folder as end-to-end encrypted
After creating a folder via WebDAV the client MUST flag the folder as end-to-end encrypted,
by sending a `PUT` request to the `/encrypted/<folder-id>` OCS endpoint where `<folder-id>` is the folder ID indicated by the WebDAV API.

Once this flag has been set the folder is only accessible by clients supporting end-to-end encryption, regular WebDAV clients cannot access it anymore.
Only empty folders can be marked as end-to-end encrypted.
Once a folder is marked as encrypted, it MUST NOT be marked as unencrypted again.

#### Create metadata file
The client MUST create the [initial metadata](#initial-metadata) by sending a `POST` request to the `/meta-data/<folder-id>` OCS API endpoint, where `<folder-id>` is the folder ID indicated by the WebDAV API.
- The encrypted metadata MUST be sent as the URL-encoded `metaData` parameter.
- The metadata signature MUST be sent as the `X-NC-E2EE-SIGNATURE` HTTP header (see [Signing the metadata](#signing-the-metadata)).
- The lock token MUST be sent as the `e2e-token` HTTP header.
  Thus the folder MUST be locked before creating the metadata, in case of a subfolder the lock of the parent folder is used
  (see [Uploading payload and metadata file](#uploading-payload-and-metadata-file)).

If metadata already exists for the folder, the server MUST respond with HTTP status code 409 Conflict.

#### Update metadata file
Every update of the metadata file MUST be done while the folder is locked.
The client locks the folder, uploads the changed files and the updated metadata file and finally unlocks the folder.
The required requests are described in [Uploading payload and metadata file](#uploading-payload-and-metadata-file).

### Modifying content of an end-to-end encrypted folder
The following steps are REQUIRED to create, update or delete files of an end-to-end encrypted folder.
If any of the following steps fail, the client MUST show a verbose warning to the user, unlock the folder and abort.

1. Make a backup of the file to be modified and the metadata file, so that in case of any upload problems the client can revert to a consistent state.
2. Detect the topmost folder which needs to be changed
   1. Increase the counter of the metadata of this folder
   2. Lock the folder with the increased counter passed as `X-NC-E2EE-COUNTER` header
3. Check for changes in the encrypted folder.
   1. If the current version is up to date, go to step 4.
   2. If not current,
      - get the latest metadata file
      - verify the metadata file
      - decrypt the metadata file
      - check if the file operation is still possible (e.g. the file to be renamed can already be deleted)
4. Perform the specific steps to create/update/delete the file or folder:
    * Create new file:
      1. Generate a new 128-bit file-key for the file
      2. Generate a new 96-bit IV for the file
      3. Encrypt the file using the key and IV with AES/GCM/NoPadding
      4. Create a new random identifier
      5. Add the new file to the files array in the metadata file with the random identifier as key and
         - filename
         - encryption key
         - nonce
         - authenticationTag
         - mimetype
    * Rename existing file:
      1. Change the filename in the files array, the encrypted file remains unchanged.
    * Update existing file:
      1. Generate a new 128-bit file-key for the file
      2. Generate a new 96-bit IV for the file
      3. Encrypt the file using the key and IV with AES/GCM/NoPadding
      4. Upload the encrypted file via WebDAV using the existing random identifier
      5. Update the file in the files array of the metadata with the updated
         - key
         - IV
         - authenticationTag
    * Delete file:
      1. Remove the corresponding entry from the files array
    * Move file into subfolder:
      1. Remove the file from the files array in the metadata file of the source folder and add it to the files array of the metadata of the target folder
      2. Perform steps 6-8 (encrypt, sign and upload the metadata) for the source and the target folder
    * Copy file into subfolder:
      1. Same as creating a new file, to prevent having the same encryption key and nonce for two different files
    * Create new subfolder:
      1. Create a new random identifier
      2. Add the folder to the folders array in the metadata file
    * Rename existing subfolder:
      1. Change the name in the folders array, the encrypted subfolder remains unchanged
    * Delete subfolder:
      1. Remove the corresponding entry from the folders array
      2. Delete the metadata of the subfolder by sending a `DELETE` request to the `/meta-data/<folder-id>` OCS endpoint
    * Move subfolder into another subfolder:
      1. Remove the folder from the folders array in the metadata file of the source folder and add it to the folders array of the metadata of the target folder
      2. Perform steps 6-8 (encrypt, sign and upload the metadata) for the source and the target folder
      3. Move the encrypted subfolder using a WebDAV `MOVE` request, the subfolder keeps its random identifier
    * Copy subfolder into another subfolder:
      1. Recursively add new folders and new files, everything MUST be re-encrypted to prevent having the same encryption key and nonce for two different files
      2. Perform steps 6-8 (encrypt, sign and upload the metadata) for every source and target folder

      _**Note:** As everything needs to be re-encrypted, this operation can be expensive for large folders, e.g. on mobile devices._
    * Delete topmost encrypted folder:
      1. Set `deleted` to `true` in the metadata
      2. Empty the files and folders array
5. Upload the modified or new encrypted file or folder, or delete the file or folder via WebDAV
6. Encrypt the metadata using the metadata-key
7. Sign the metadata as described in [Signing the metadata](#signing-the-metadata)
8. Upload the encrypted metadata
9. Unlock the folder

#### Uploading payload and metadata file
To keep the metadata and the file in sync locking is REQUIRED.
The client MUST lock the topmost encrypted (sub-)folder which needs to be changed and pass the incremented counter as header.
The lock also covers all subfolders of the locked folder.
The server MUST check that the incremented counter is greater than the counter of the last lock of this folder, if not it MUST fail with HTTP status code 412 Precondition Failed.
If the folder (or one of its parent folders) is already locked, the server MUST respond with HTTP status code 423 Locked.
If the lock operation succeeded, the server responds with HTTP status code 200 together with a lock token in the response body.
In case the client lost connection after locking the folder, it MAY restart the operation later with another lock request.
In this case the client MUST send the lock token with the new lock request.
This enables the server to decide if the client is allowed to retry the upload.

After locking was successful, the client
- uploads the encrypted file
- uploads the metadata file with the signature as header

After both files are uploaded successfully the client finishes the operation by sending an unlock request.
All changes done while the folder is locked are only applied by the server when the folder is unlocked.

The `<folder-id>` denotes the ID of the end-to-end encrypted folder given by the WebDAV API.

To lock the folder the client MUST send a `POST` request to the `/lock/<folder-id>` endpoint.
- The incremented counter MUST be sent as the `X-NC-E2EE-COUNTER` HTTP header.
- To reuse an existing lock token it MUST be sent as the `e2e-token` parameter.
- The server returns the lock token as the `e2e-token` key of the response data.

All WebDAV requests modifying the content of a locked folder (e.g. `PUT`, `MKCOL`, `MOVE`, `COPY` or `DELETE`) MUST include the lock token as the `e2e-token` HTTP header.

To update the metadata the client MUST send a `PUT` request to the `/meta-data/<folder-id>` endpoint.
- The computed signature MUST be sent as the `X-NC-E2EE-SIGNATURE` HTTP header.
- The current lock token MUST be sent as the `e2e-token` HTTP header.
- The encrypted metadata JSON MUST be sent as the URL-encoded `metaData` parameter.

If the folder is not locked with the given token, the server MUST respond with HTTP status code 412 Precondition Failed.

To unlock the folder the client MUST send a `DELETE` request to `/lock/<folder-id>`.
- The previously received lock token MUST be sent as the `e2e-token` HTTP header.
- To discard all changes done while the folder was locked, the client MAY send the parameter `abort` with the value `true`.
  The server then reverts the changes to the state before the folder was locked.

If unlocking fails, the client MUST retry or abort the operation so that the folder is again in an unlocked and consistent state.

#### Locking scope examples
_This section is informative._

- `/enc/folderA/test` shall be moved into `/enc/folderA/subfolderB/`
  - the topmost folder to change is in that case `folderA`, so this needs to be locked and other subfolders of `/enc` are still accessible
  - the metadata of `/enc/folderA` and `/enc/folderA/subfolderB` needs to be handled correctly, e.g. with the counter
- `/enc/folderA/test` shall be moved into `/enc/folderB/`
  - the topmost folder to change is in that case `/enc`, so this needs to be locked, thus the complete encrypted directory is locked

### Accessing content of an end-to-end encrypted folder

#### Encrypted folder gets added
- The WebDAV endpoint lists the folder with the `{http://nextcloud.org/ns}is-encrypted` property set to `1`.
  The metadata of the folder is also available as `{http://nextcloud.org/ns}e2ee-metadata` WebDAV property.
- The client SHOULD show a lock symbol when listing the folder.
- The client MUST refuse to update the encryption status to false as this is not allowed.
  If the server sends such an information the client MUST warn the user.
- Upon entering an encrypted folder the client continues with [Accessing encrypted files](#accessing-encrypted-files).

#### Encrypted folder gets deleted
If the WebDAV endpoint does not list an encrypted folder anymore, the client MUST check if this is a valid delete.
Therefore, the client MUST request the metadata using a `GET` request to the `/meta-data/<folder-id>` OCS endpoint, validate the metadata file and check if `deleted` is set to `true`.
Otherwise, the client MUST display a warning that the folder was maliciously deleted and MUST refuse to delete the locally synced content.

#### Accessing encrypted files
No locking is required to read files of an encrypted folder.
If the folder is locked due to an ongoing upload, the server responds with HTTP status code 423 Locked.
The client MAY then present the currently stored files alongside with a warning and SHOULD disable (on mobile) or postpone (on desktop) any file operation.
To access encrypted files the client MUST perform the following steps:

1. Check for changes in the encrypted folder.
   If not current, download the latest metadata file of the encrypted folder.
2. Verify the metadata file as described in [Verifying the metadata](#verifying-the-metadata)
3. Decrypt the metadata file using the metadata-key of the topmost encrypted folder
4. Look up the file-metadata of the files in the `files` array of the decrypted metadata
5. Download the referenced files by their random identifier using WebDAV
6. Decrypt the file
    1. Get the key from the metadata file
    2. Get the IV from the metadata file
    3. Get the authenticationTag from the metadata file
    4. Decrypt using AES/GCM/NoPadding (128bit) using the key and IV
    5. Validate decryption using authenticationTag

In case a file is referenced in the metadata but cannot be found on the WebDAV file system the client SHOULD warn the user.
If the file exists locally but not on the WebDAV file system the client SHOULD re-upload the file.
In case the number of files referenced in the encrypted metadata differs from the number of files on the file system, the client SHOULD display a warning to the user.

### Migrating filedrop
Files added via secure file drop are added to the filedrop array, e.g. via the web browser.
The filedrop-key, similar to the metadata-key, is encrypted to all users of this folder, so that all users that have access can migrate.

To add entries to the filedrop array a `PUT` request to the `/meta-data/<folder-id>/filedrop` OCS endpoint MUST be sent.
- The new entries MUST be sent as the URL-encoded `filedrop` parameter, a JSON object mapping the random identifiers to the encrypted entries.
- The server merges the new entries into the filedrop array of the metadata.
- No lock token is required and the counter is not changed, as the filedrop array is not part of the signed metadata.

As soon as a client downloads a metadata file and finds a non-empty filedrop array, it MUST:

1. lock the folder
2. move each file from the filedrop array to the files array
3. empty the filedrop array
4. upload the updated metadata file
5. unlock the folder

This MUST be done even when there is no actual change on other files, so e.g. when listing files, refreshing folders, etc.
The reason is that the filedrop array is not protected via any mechanism, see [Accepted risks](#accepted-risks).
Thus the time filedrop entries exist SHOULD be kept as short as possible.

### Sharing encrypted folders to other users

#### Key discovery of other users
The clients MUST do the following when trying to establish a trust relationship to another user:

1. Check if a certificate for the specified user ID is already downloaded (Trust On First Use (TOFU))
   1. If a certificate is available, it MUST be used
   2. If none is available, the client continues at 2.
2. Query the user certificate by sending a `GET` request to the `/public-key` endpoint with a JSON encoded `users` parameter containing the specified user IDs
3. If the user has not yet set up end-to-end encryption and thus has no public key, it is not possible to share with the user.
   A warning SHOULD then be shown.
4. Verify that the certificate is issued by the downloaded server public key.
   1. If yes: Use this certificate.
   2. If no: The client MUST NOT initiate the encrypted share and SHOULD show a warning to the user.
5. Store the user certificate locally for next operations

#### Add someone to an end-to-end encrypted folder
To create a share the following actions MUST be performed:

1. The folder is shared via the [OCS sharing](https://docs.nextcloud.com/server/latest/developer_manual/client_apis/OCS/ocs-share-api.html) API to the recipient
2. Generate a new metadata-key
3. Add the recipient to the users array with
   - userId
   - certificate
4. Add or replace the new metadata-key of every user in the users array.
   The metadata-key is encrypted with the user's public key.
5. Add the SHA-256 hash of the metadata-key to the keyChecksums array.
6. Encrypt the metadata of all subfolders with the new metadata-key and upload it.

#### Remove someone from an existing share
To remove someone from an existing share the following actions MUST be performed:

1. The folder is unshared via the [OCS sharing](https://docs.nextcloud.com/server/latest/developer_manual/client_apis/OCS/ocs-share-api.html) API
2. Generate a new metadata-key
3. Remove the recipient from the users array
4. Add or replace the new metadata-key of every user in the users array.
   The metadata-key is encrypted with the user's public key.
5. Add the SHA-256 hash of the metadata-key to the keyChecksums array.
6. Encrypt the metadata of all subfolders with the new metadata-key and upload it.

### Sharing to external users
To share end-to-end encrypted files with users without a Nextcloud account,
it is possible to create public shares with end-to-end encryption.
For this the topmost encrypted folder MUST be shared with the Nextcloud sharing flow as a link share.
Then a key pair MUST be generated as described for the initial device, with the following changes:
- For the requests to the `/public-key` and `/private-key` endpoints the `shareToken` parameter,
  with the value of the token of the created share, MUST be included.
- The `CN` of the certificate MUST be set to `s:SHARE_TOKEN`,
  where `SHARE_TOKEN` is replaced with the token of the share.

This new share user MUST be added just like a normal user to the metadata.
To distinguish between share users and normal users the user ID can be checked for the `s:` prefix as the colon character is not allowed in normal user IDs.
When a share user is added to the users array, the metadata version MUST be set to `"2.1"`.

The generated private key MUST be encrypted as described for the initial device with a newly generated mnemonic,
and is stored on the server under the `s:SHARE_TOKEN` ID.
The client SHOULD then provide the new mnemonic to the sharing user, who has to provide this information
to the share recipient using a secure second channel.

The share recipient MUST include the share token as the `X-NC-E2EE-SHARE-TOKEN` HTTP header in all OCS API requests,
e.g. to download the private key, to lock the folder or to access the metadata.
Only for adding filedrop entries the share token is sent as the `shareToken` parameter.

## HTTP API
This protocol makes use of two different APIs:
1. The [Nextcloud WebDAV](https://docs.nextcloud.com/server/latest/developer_manual/client_apis/WebDAV/index.html) API
2. The `end_to_end_encryption` [OCS](https://www.open-collaboration-services.org/) API

When an OCS API endpoint is mentioned then this document uses the `v2` endpoint of OCS provided by Nextcloud.
So that all OCS requests share the same base URL:

- `/ocs/v2.php/apps/end_to_end_encryption/api/v{VERSION}`

Where `{VERSION}` is the major version of the current metadata version.

## Security considerations

### Accepted risks
* Leaking the number of files in an encrypted folder is an accepted risk.
* Leaking the name of the topmost encrypted folder is an accepted risk.
* Leaking which file operation has been performed on files in an encrypted folder is an accepted risk.
* Filedrop: there can be no sanity check if the filedrop array was modified (e.g. deleting files on the server), as it is not part of the signed metadata.
  Thus an attacker can remove files and filedrop entries, so that users will not receive the uploaded files.
  As attackers cannot decrypt those files, as they do not have access to the filedrop-key, this "data loss" is accepted.
* A new sharee cannot verify the encryption status of a shared folder, see [Attacker advertises new share as unencrypted](#attacker-advertises-new-share-as-unencrypted-to-a-new-sharee-instead-of-encrypted).

### Attack scenarios

#### Replay attack
- An attacker reverts the metadata file and payload to any previous state (e.g. malicious admin).
- Upon next sync at least the client with the latest sync can detect this attack by checking the counter.
- There will always be at least one client that has the latest sync state (the client which issued the latest change).
- Limitations:
    - it can happen that the client with the latest sync state is offline and thus the detection will be delayed.
      In the worst case scenario it will never be detected, if the client never syncs again.
    - meanwhile other clients cannot detect the replay attack and will do file/folder operations as usual.
- No encrypted data can be decrypted by this attacker.

#### Removed sharee tries to re-add itself
Given a share with User A, B and C.
User C is removed by User A at a later time.
User C now tries to gain access to the share again by first adding itself via Nextcloud share API.
User C adds itself to users array of metadata file again.
User C does not know the metadata-key that was generated when user C was removed.
So if user C creates a new metadata-key to get access, the checksum of the metadata-key generated on removal is missing in keyChecksums.
User A/B can now detect the malicious attack as a hash has been removed from keyChecksums.
If user C instead keeps the encrypted metadata, user C cannot decrypt it, but the same considerations as in the next scenario apply.

#### User with valid certificate tries to add themselves
In this scenario the attacker is a valid user of the Nextcloud instance and therefore has a certificate issued by the Nextcloud server or trusted CA.
Main idea of the attack:
- The attacker adds themselves to the users array and waits until a new metadata-key is used.
- The new metadata-key will be encrypted with the public key of the attacker.

The signature on its own does not prevent this attack.
Creating the signature does not require the metadata-key and the signer is looked up in the users array,
so the attacker can create a valid signature with their own certificate after adding themselves.

The attacker cannot modify the encrypted part of the metadata, as this requires the metadata-key.
Thus the users array changed, but the counter was not increased.
Only clients that know the latest metadata are able to detect this, e.g. a newly added device cannot.

_**Note:** Detecting this scenario is not yet covered by the checks described in [Verifying the metadata](#verifying-the-metadata)._

#### Attacker deletes topmost folder and/or metadata file on server
- The attacker deletes either the metadata file, the WebDAV folder or both on the server.
- The client detects this on the next sync:
  - if the metadata file is missing or corrupt, the client warns the user and refuses to delete the local content
  - if the folder is missing on the WebDAV endpoint, the client downloads the latest metadata file and checks for the deleted flag
  - if the deleted flag is set to true, the client accepts this as a regular folder deletion
  - if the metadata file and the WebDAV files are missing, the client warns the user and refuses to delete the local content

#### Attacker advertises new share as unencrypted to a new sharee instead of encrypted
- The encryption status of a shared folder cannot be guaranteed for a new sharee, because of the TOFU assumption.
- The user is responsible to make a plausibility check if the folder name and the context of the files and folders should be encrypted and to detect such a scenario.

### Handling of complete key material loss
Right now a complete key material loss means that other users that already had a share with the user will not be able to share new encrypted folders since the protocol uses TOFU for initiating shares.

However, considering the fact that the user has a mnemonic passphrase to recover their key and any connected device (e.g. their smartphones) also has a way to recover the mnemonic we consider this an edge-case at the moment.

We are investigating how a CSR approach here could help in such edge-cases at least to allow new shares again.

## Versioning and backward compatibility

### Metadata versions
The `version` key of the metadata MUST be one of the following values:
- `"2.0"`: metadata as specified in this document
- `"2.1"`: metadata containing share users in the users array, see [Sharing to external users](#sharing-to-external-users)

Clients MUST support both versions.
Clients MUST NOT use metadata of an unsupported version.

The major version of the metadata selects the version of the OCS API, see [HTTP API](#http-api).

### Legacy private key encryption
Private keys uploaded with an older version of this protocol use different key derivation parameters.
If decrypting the private key with the current parameters fails, the client MUST try the following settings:
1. PBKDF2WithHmacSHA1 as key derivation with 1024 iterations
2. PBKDF2WithHmacSHA1 as key derivation with 600000 iterations
3. PBKDF2WithHmacSHA256 as key derivation with 600000 iterations

### Version 1
Version 1 of this protocol is specified in [RFC_v1.md](./RFC_v1.md).
Metadata with a version `"1.7"` was only used as an internal prototype of version 2.0 for file drop support.

## Appendix: Possible extensions
_This section is informative._

### Manual key verification
The clients could expose QR-codes of their public keys to make manual verification of other users' public keys possible.

### Hardware security module (HSM)
A HSM would act as trusted third party and would eliminate the Nextcloud server from the key exchange process completely.
I.e. it could replace trust on first use with a central trusted certificate authority (CA).
The CA also would make key revocation possible with a certificate revocation list CRLs or OCSP.
To implement CRLs the clients would always check if a key was revoked before they encrypt something with a given key.
