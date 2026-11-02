# Nextcloud end-to-end encryption

## Table of contents

* [Introduction](#introduction)
* [Protocol design goals](#protocol-design-goals)
  * [Usage of widely available and tested libraries for crypto primitives](#usage-of-widely-available-and-tested-libraries-for-crypto-primitives)
  * [Sharing functionality](#sharing-functionality)
  * [Optional central data recovery](#optional-central-data-recovery)
  * [Simple multi-device management](#simple-multi-device-management)
  * [Simple authenticated key exchange](#simple-authenticated-key-exchange)
  * [Support for HSM](#support-for-hsm)
  * [Versioning](#versioning)
* [Accepted feature loss](#accepted-feature-loss)
* [Security goals](#security-goals)
  * [Attacker model](#attacker-model)
  * [Goals](#goals)
* [Technical implementation](#technical-implementation)
  * [Terminology](#terminology)
  * [API endpoints](#api-endpoints)
  * [Adding an end-to-end encrypted device](#adding-an-end-to-end-encrypted-device)
  * [Creating an end-to-end encrypted folder](#creating-an-end-to-end-encrypted-folder)
  * [Signing the metadata](#signing-the-metadata)
  * [Verifying the metadata](#verifying-the-metadata)
  * [Modifying and accessing content of an end-to-end encrypted folder](#modifying-and-accessing-content-of-an-end-to-end-encrypted-folder)
  * [Sharing encrypted folders to other users](#sharing-encrypted-folders-to-other-users)
  * [Sharing to external users](#sharing-to-external-users)
  * [Edge cases](#edge-cases)
* [Possible extensions](#possible-extensions)
  * [Manual key verification](#manual-key-verification)
  * [Hardware security module (HSM)](#hardware-security-module-hsm)
* [Scenarios](#scenarios)
  * [Regular operations](#regular-operations)
  * [Attack scenarios](#attack-scenarios)

## Introduction
With the announcement of the Nextcloud end-to-end encryption techpreview, we would like to invite you to scrutinize our source code and cryptographic approach.

Please note that end-to-end encryption feature is a work-in-progress and this document may describe functionalities or approaches not yet implemented in our testing releases. 
This document is meant as authoritative implementation guideline for our clients. 
For the sake of having smaller and incremental steps towards the final implementation we are going to continuously release updated builds of our clients.

We are looking forward to your input to refine our approach towards client-side encryption. 
In addition, we will also make sure to validate our approach on time by external cryptographic experts.

## Protocol design goals
The end-to-end encryption has to fulfill the following business and technical criteria.

### Usage of widely available and tested libraries for crypto primitives
We believe that for security-sensitive functionalities relying on existing and proven libraries is an essential requirement. 
Thus we require that:

* The used library for cryptographic primitives must be in use widely.
* The used library for cryptographic primitives has undergone successful security audits.

Also due to our wide range of supported systems, the library must be available for the following of our supported environments:

* iOS 9+
* Android 6.0+
* Mac OS X 10.9+
* Windows 7+
* commonly used Linux distributions
* PHP 7.0+

_**Note:** While we do not have any current plans to add support for potential server-side decryption we want to keep this possibility open for the future._

### Sharing functionality
Existing client-side encryption solutions often prevent the sharing of encrypted files, the Nextcloud end-to-end encryption must offer support for the following sharing scenarios:

* Sharing encrypted folders with other users
* Any user that is part of the shared folder is able to add new users to the share

The following sharing scenarios are considered out of-scope:

* Sharing single files or folders from an encrypted folder
* Sharing encrypted folders with whole groups
* Sharing subfolders of encrypted folders is not possible

### Optional central data recovery
While End-to-End encryption is meant to prevent access to data for other parties the reality is: People may lose their encryption keys.

While in a home user environment this might be acceptable, in an enterprise this can have grave implications.
Thus an optional central data recovery has to be available offering the following capabilities:

* Central recovery key per instance can be generated
* Central recovery key must not be stored on the instance and can be safely exported (e.g. to be stored in a physical vault)
* All data will also be encrypted with the central recovery key when enabled
* Users must be prominently warned in the UI of their clients if a central data recovery key is enabled
* When a central data recovery key is enabled the existing end-to-end encrypted folders must not be affected

### Simple multi-device management
Access to encrypted data should easily be possible from any device the end-user owns, this includes all mobile devices as well as desktop devices.

Thus:
* Sharing keys between existing devices must be frictionless
* Newly added devices should have access to all previously encrypted data

### Simple authenticated key exchange
Key exchange is a key problem of any cryptographic system.
On one hand one wants to ensure that the key of the participating parties is authentic.
On the other hand, manual comparison of key material is cumbersome and rarely something that regular users can be bothered to do.

A secure and yet simple system has to implement the following properties:
* Key exchange between parties should be frictionless
* Optionally, clients can offer key verification by comparing certificate fingerprints (e.g. by using QR-Codes)

### Support for HSM
To fulfill enterprise security requirements it should be possible that key material is generated by a hardware security module.
Thus offering strong authentication, tampering resistance and a complete audit trail.

### Versioning
The protocol has to support versioning in case of future changes in the metadata or cryptographic parameters.

## Accepted feature loss
Since the data is not accessible to the server and to simplify the implementation, losing following features is acceptable:

* Server-side trash bin
* Server-side versioning
* Server-side search
* Server-side previews
* Sharing to groups
* Sharing at the level of individual files
* Sharing of subfolders of an encrypted folder. It is only possible to share topmost encrypted folder
* Filedrop: due to implementation there can be no sanity check if filedrop could have been modified (deleting files on server). Thus it is acceptable that an attacker can remove files and filedrop array, so that users will not have uploaded files. As attackers cannot decrypt those files, this "data loss" is acceptable.
* Scanning with files_antivirus. Metadata are also ignored by files_antivirus, even though they could be scanned, it adds too much latency.

## Security goals
### Attacker model
The end-to-end encryption must protect against an attacker with following capabilities:

* Attacker can circumvent underlying TLS/SSL transport encryption
* Attacker has full control over the server (e.g. compromised server or malicious admin)
* Attacker cannot tamper with key exchange between clients and with initial connection of a new client to a share (Trust on first use (TOFU))
  * Future support for separate trusted key server could avoid the TOFU compromise and therefore protect against a stronger attacker.
* Removed users: A user who is part of a shared end-to-end encrypted folder is trusted until the user has been removed

### Goals
The protocol must achieve following goals when assuming an attacker as specified above.

* Access to ciphertext must not leak file content nor file names nor the names of subfolders.
  * Leaking the number of files in an encrypted folder is an accepted risk.
  * Leaking the name of the topmost encrypted folder is an accepted risk.
  * Leaking which file operation has been performed on files in an encrypted folder is an accepted risk.
* Once a user has been removed from an encrypted folder they should have no relevant key material to decrypt files updated or created in the future
* **Confidentiality**: No one, except the legitimate recipients, must have access to the encrypted documents.
* **Integrity**: Even with writable access to the ciphertext one must not be able to tamper with the data unnoticed.
    In case the number of files referenced in the encrypted metadata differs from the number of files on the file system, a warning should be displayed to the user.
* **Authentication**: all valid changes (uploading new files, changing existing files, removing existing files) to an end-to-end encrypted folder must only be made by a user who is part of the (shared) folder. 
   Malicious changes are detected at the latest when the client that made the most recent valid change synchronizes the next time.

## Technical implementation
The encryption is based upon an asymmetric cryptographic system.
The following steps will walk through the technical implementation of the encryption.

### Terminology
* Device: a device can be anything able to run one of our supported clients.
* file-metadata: cleartext name, mimetype, file-key, nonce/iv and authTag of a file
* file-key: the actual key used to encrypt the file
* folders-array: associative array mapping random identifiers names to folder name
* files-array: associative array mapping random identifiers names to the (encrypted) metadata of the file
* users-array: array of information of users. Used to list all users of a shared and encrypted folder, with their certificate and the encrypted metadata key
* metadata-key: key used to encrypt the metadata of the folder
* filedrop-key: key used to encrypt a single entry of the filedrop array
* metadata: metadata of all files (file-metadata) and sub-folders in the encrypted folder, list of checksums of metadata-keys and a counter
* PEM: Textual encoding of certificate and key structures according to [RFC 7468](https://datatracker.ietf.org/doc/html/rfc7468)

### API endpoints
This RFC makes use of two different APIs:
1. The [Nextcloud WebDAV](https://docs.nextcloud.com/server/latest/developer_manual/client_apis/WebDAV/index.html) API
2. The `end_to_end_encryption` [OCS](https://www.open-collaboration-services.org/) API

When an OCS API endpoint is mentioned then this RFC uses the `v2` endpoint of OCS provided by Nextcloud.
So that all OCS requests share the same base URL:

- `/ocs/v2.php/apps/end_to_end_encryption/api/v{VERSION}`

Where `{VERSION}` is the major version of the current metadata version.

### Adding an end-to-end encrypted device
When requesting the server certificate and when adding a new device of a user, we assume that the server is trusted (TOFU).
As a first step, a device has to be added to an account.
Depending on whether an end-to-end encrypted device already has been added to an account, the device will have to create new key material or use existing key material.

To check whether a certificate has already been issued or not the `/public-key` OCS endpoint should be used. 
In addition, the client has to download the server’s public key from the `/server-key` OCS endpoint and use this to verify the certificate chain in all future operations.

Alternatively, an external certificate authority may be used with certificates being generated and their lifetime tracked outside of the end_to_end_encryption Nextcloud app. That would be the case if certificates (and their associated key-pair) are stored on dedicated USB tokens.

#### Initial device
When a device is initially added to an account the device has to generate all relevant key material for the user account and provision those on the server:

1. Client has to generate a new X.509 Certificate Signing Request (CSR), following [RFC 2986](https://datatracker.ietf.org/doc/html/rfc2986), and private key
  1. `CN` of X.509 certificate must be set to the currently logged-in user ID
2. Client uploads the X.509 CSR to the server
  1. The client encodes the CSR using PEM encoding
  2. The client transmits the CSR as a URL-encoded `POST` parameter `csr` to the `/public-key` OCS API endpoint.
3. Server issues a certificate if the `CN` matches the current user ID.
4. Server returns the issued certificate.
5. Client verifies their certificate was signed by the server by verifying the signature using the previously fetched public key of the server.
6. Client stores the private key and the certificate in the keychain of the device.

In a second step, the private key will be stored encrypted on the server to simplify the addition of further devices:

1. Client generates a 12 word long mnemonic from the English `BIP-0039` word list. The word list contains 2048 words, thus resulting in 2048^12 possible key combinations.
2. Client encrypts the private key
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
3. Client uploads the encrypted private key (including the authenticationTag), nonce and salt to the server
  1. key, salt, and nonce are Base64 encoded
  2. Then concatenated using `|` as the separator (`{base64(key + authenticationTag)}|{base64(nonce)}|{base64(salt)}`)
  3. This string is then sent as the URL-encoded `POST` parameter `privateKey` to the `/private-key` OCS endpoint.
4. The mnemonic is displayed to the user as a space-separated text and the user is asked to note it down in a secure place.
  For encrypting/decrypting, the mnemonic must have no whitespace and be lowercase.
5. The mnemonic is stored in the keychain of the device with spaces so it can be shown more readable.

In case a user loses their device, they can easily recover by using the mnemonic passphrase. 
The mnemonic passphrase can also be shown in the client settings in case the user forgets their mnemonic. 
Displaying the mnemonic requires the user to enter their PIN/fingerprint again on mobile devices.

#### Initial device with hardware USB token storage of certificate

When a device is initially added to an account the device will have to upload relevant key material for the user account on the server:

1. Client will discover on secure storage the proper certificate (and key pair) to use
2. Client uploads their certificate to the server using the OCS `POST` endpoint `/public-key`
3. Client may check the certificate of the server by using `GET` on the `/server-key` OCS endpoint.
4. Client stores the certificate ID and enables end-to-end encryption feature on the client.

#### Further devices
In case a certificate already exists for the user the client has to download the existing private key. 
This is done the following way:

1. Client downloads private key from the `/private-key` endpoint.
2. Client asks the user for the mnemonic and decrypts the private key using AES/GCM/NoPadding as cipher (256 bit key size) and PBKDF2WithHmacSHA256 as key derivation with 600000 iterations. Alternatively the client should use the former algorithm and parameters in case the private key was uploaded with an older RFC version. A client must try the following settings:
  1. PBKDF2WithHmacSHA1 as key derivation with 1024 iterations
  2. PBKDF2WithHmacSHA1 as key derivation with 600000 iterations
  3. PBKDF2WithHmacSHA256 as key derivation with 600000 iterations
3. Client checks if private key belongs to previously downloaded public certificate.
4. Client checks if their certificate was signed by the server (checking the server's public key from the OCS `/server-key` endpoint)
5. Client stores the private key in the keychain of the device.
6. The mnemonic is stored in the keychain of the device (ideally with spaces so it can be shown more readable).

#### Updating a user certificate

A user certificate may expire or be revoked and renewed if needed. In such case, a migration will be needed as the key pair will change and metadata keys encrypted with the former public key will no longer be accessible.

The certificate migration will happen at initiative from one Files client of the specific concerned user. That user will trigger the certificate migration. During that process the following steps need to happen:

- prerequisite is that all currently encrypted folders are synced by the client that will do a certificate change or renewal. The user interface of clients should make this blocking before performing the migration.
- on demand certificate migration is still possible as a fallback
- replace the certificate that is currently stored on the server
- identify all folders having files currently accessible from this user and for each of them:
  - decrypt the metadata key associated to each file for accessible by this user
  - encrypt it with the new public key
  - upload the metadata file again with the new encrypted metadata key and the new certificate (without the private key)
  - sign the metadata file by the new user certificate

During that process the usual process to modify one folder metadata file has to be followed as described in [Update metadata file](#update-metadata-file).

### Creating an end-to-end encrypted folder
To create an end-to-end encrypted folders multiple steps have to be performed.
First of all, data access to such folders happens via our regular WebDAV API available at `/remote.php/dav/{userId}/files`.

#### Mark folder as end-to-end encrypted
After creating a folder via WebDAV the folder has to be flagged as end-to-end encrypted.
This can be performed by sending a `PUT` request to the `/encrypted/<folder-id>` OCS endpoint where `<folder-id>` has to be the folder ID indicated by our WebDAV API.

Once this flag has been set the folder will not be accessible anymore via web and also not displayed to regular WebDAV clients.
Only empty folders can be marked as end-to-end encrypted.
Once a folder is marked as encrypted, it cannot be marked as unencrypted again.

#### Create metadata file
Every folder contains a metadata file containing the following information:

* metadata of all files (file-metadata) and sub-folders
* list of checksums of metadata-keys
* users array
* counter

The metadata is a JSON document with the following structure depicted below.
We use a notation with inline comments (`//`) for better readability.
Note that comments are not available in standalone JSON and only used here for better understanding.

In case the central data recovery key is enabled the metadata will also be encrypted towards the server's central data recovery key. Clients must show a prominent warning to the users for such scenarios.

The JSON document contains at least 3 keys and at most 4 keys:
- `metadata`: The value is the encrypted inner metadata
- `users`: The list of users with access to the folder
- `version`: The metadata version, either `"2.0"` or `"2.1"` if the users array contains users of public shares (see [Sharing to external users](#sharing-to-external-users))
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

When creating a new folder, an initial metadata file needs to be created with following values
- counter starts with 0
- if folder is topmost encrypted folder
  - generate a new metadata-key
  - the users array contains the current user with userId, certificate and encrypted metadata-key
- if folder is a subfolder of an encrypted folder
  - the metadata-key of the topmost encrypted folder is used, all subfolders share the metadata-key of their topmost encrypted folder
  - the users-array is not included

The metadata has to be created by sending a `POST` request to the `/meta-data/<folder-id>` OCS API endpoint, where `<folder-id>` has to be the folder ID indicated by our WebDAV API.
- The encrypted metadata has to be sent as the URL-encoded `metaData` parameter.
- The metadata signature has to be sent as the `X-NC-E2EE-SIGNATURE` HTTP header (see [Signing the metadata](#signing-the-metadata)).
- The lock token has to be sent as the `e2e-token` HTTP header.
  Thus the folder has to be locked before creating the metadata, in case of a subfolder the lock of the parent folder is used
  (see [Uploading payload and metadata file](#uploading-payload-and-metadata-file-step-5--8)).

If metadata already exists for the folder, the server responds with HTTP status code 409 Conflict.

#### Update metadata file
Every update of the metadata file has to be done while the folder is locked.
The client locks the folder, uploads the changed files and the updated metadata file and finally unlocks the folder.
The required requests are described in [Uploading payload and metadata file](#uploading-payload-and-metadata-file-step-5--8).

#### Migrating filedrop
Files added via secure file drop are added to filedrop array via web browser.
The filedrop-key, similar to metadata-key, is then encrypted to all users of this folder, so that all users that have access can migrate.

To add entries to the filedrop array a `PUT` request to the `/meta-data/<folder-id>/filedrop` OCS endpoint has to be sent.
- The new entries have to be sent as the URL-encoded `filedrop` parameter, a JSON object mapping the random identifiers to the encrypted entries.
- The server merges the new entries into the filedrop array of the metadata.
- No lock token is required and the counter is not changed, as the filedrop array is not part of the signed metadata.

As soon as a client downloads metadata file and finds a non-empty filedrop array, they shall do

1. lock folder
2. move each file from filedrop array to files array
3. empty filedrop array
4. upload updated metadata file
5. unlock folder

This needs to be done even when there is no actual change on other files, so e.g. when listing files, refreshing folders, etc.
Reason is that filedrop array is not protected via any mechanism and thus an attacker could remove array and payload and thus no user knows about this uploaded file.
The attacker cannot decrypt it, as they do not have access to the filedrop key.
Thus it is best to keep time for existing filedrop as little as possible.

### Signing the metadata
Signature: Cryptographic Message Syntax (CMS) signed data, according to [RFC 5652](https://datatracker.ietf.org/doc/html/rfc5652)
- certificate of user
- Signed data:
   - Create metadata JSON in a compact format
      - Remove the filedrop part
      - Stringified without spaces and newlines (except in keys or values)
      - Object keys are sorted alphabetically
   - Encode the JSON string with Base64 prior signing
   - SignerIdentifier of the CMS container contains userId of the user who created the signature
   - Must include the signed attributes described in [RFC 6488](https://www.rfc-editor.org/rfc/rfc6488.html)

The encoded binary CMS structure is base64-encoded and sent in the header of the metadata request.
The Section [Uploading payload and metadata](#uploading-payload-and-metadata-file-step-5--8) further describes how the signature is handled.
***A CMS Signature MUST be always generated with detached mode (the metadata is not included in the signature as it is already stored on the server and is always retrieved with a GET request***
***A metadata for a CMS Signature MUST be prepared as described at the beginning of this section (without spaces and newlines and also base64 encoded when passing it to signature generation API***

### Verifying the metadata
Before using the metadata file, e.g. on a folder refresh the client has to verify the signature.
The signature is returned as the `X-NC-E2EE-SIGNATURE` HTTP response header of the `GET` request to the `/meta-data/<folder-id>` OCS endpoint.
It is also available as the `{http://nextcloud.org/ns}e2ee-metadata-signature` WebDAV property of the folder.

To verify the signature the client has to:
1. Prepare the signed data from the metadata as described in [Signing the metadata](#signing-the-metadata).
2. Find the user identified by the SignerIdentifier of the CMS signature in the `users` array of the topmost encrypted folder.
3. Verify the CMS signature using the certificate of this user.

After the signature was verified, the client has to find its metadata-key in the `users` array and decrypt it to decrypt the metadata.

If any of the following checks fail, the client needs to refuse further sync and informs the user:
- check counter: new counter must be greater than locally stored counter
- check signature
- check that hash of metadata-key is in keyChecksums
- check that no hash has been removed from the keyChecksums
- check if cert of all users is issued by the CA

### Modifying and accessing content of an end-to-end encrypted folder
The following steps are required to create, update, delete files of an end-to-end encrypted folder.
If any of the following steps fail, show a verbose warning to the user, unlock the folder and abort.

1. Make a backup of the file to be modified and the metadata file, so that in case of any upload problems the client can revert to a consistent state.
2. Detect topmost folder which needs to be changed
  1. Increase counter of the metadata of this folder
  2. Lock the folder with increased counter passed as header X-NC-E2EE-COUNTER
3. Check for changes in the encrypted folder.
  1. if current version is up to date, go to next step 4.
  2. If not current,
    - get the latest metadata file
    - verify metadata file
    - decrypt metadata file
    - check if file operation is still possible (e.g. file to be renamed can already be deleted)
4. Perform specific steps to create/update/delete file or folder:
    * Create new file:
      1. Generate a new 128-bit encryption key for the file and encrypt it using AES/GCM/NoPadding
      2. Generate a new 96-bit IV for the file
      3. Encrypt the file using the key and IV with AES/GCM/NoPadding
      4. Create new random identifier by generating a random UUID and removing the dash (`-`). The identifier must follow `/^[0-9a-fA-F]{32}$/`
      5. Add new file to the files array in the metadata file with UUID as identifier and 
        - filename
        - encryption key
        - nonce
        - authenticationTag
        - mimetype
    * Rename existing file:
      1. Change filename in files array, the encrypted file remains unchanged.
    * Update existing file:
      1. Generate a new 128-bit encryption key for the file and encrypt it using AES/GCM/NoPadding
      2. Generate a new 96-bit IV for the file
      3. Update the metadata of the file in the files-array
      4. Use the existing random identifier for the encrypted file when uploading it via WebDAV
      5. Encrypt the file using the key and IV with AES/GCM/NoPadding
      6. Use the existing random identifier for the file and upload the encrypted file via WebDAV using the existing random identifier as file ID
      7. Update the file in the files array of the metadata with updated
        - key
        - IV
        - authenticationTag
    * Delete file:
      1. Remove the corresponding entry from the files array
    * Move file into subfolder:
      1. Remove file from files array in metadata file of source folder and add it to metadata files array in target folder
      2. Steps 6-8 (encrypt, sign and upload the metadata) need to be done for source and target folder
    * Copy file into subfolder: 
      1. Same like create new file, to prevent having the same encryption key and nonce for two different files
    * Create new subfolder:
      1. Create new random identifier by generating a random UUID and removing the dash (`-`). The identifier must follow `/^[0-9a-fA-F]{32}$/`
      2. Add folder to folders array in the metadata file
    * Rename existing subfolder:
      1. Change filename in folders array, the encrypted subfolder remains unchanged
    * Delete subfolder:
      1. Remove the corresponding entry from the folders array
      2. Delete the metadata of the subfolder by sending a `DELETE` request to the `/meta-data/<folder-id>` OCS endpoint
    * Move subfolder into another subfolder:
      1. Remove folder from folders array in metadata file of source folder and add it to metadata folders array in target folder
      2. Steps 6-8 (encrypt, sign and upload the metadata) need to be done for source and target folder
      3. Move the encrypted subfolder using a WebDAV `MOVE` request, the subfolder keeps its random identifier
    * Copy subfolder into another subfolder:
      1. Recursively add new folders and new files, everything needs to be re-encrypted to prevent having the same encryption key and nonce for two different files
      2. Steps 6-8 (encrypt, sign and upload the metadata) need to be done for every source and target folder

      _**Note:** As everything needs to be re-encrypted, this operation can be expensive for large folders, e.g. on mobile devices._
    * Delete topmost encrypted folder
      1. Set deleted to true in metadata array
      2. empty files and folders array
5. Upload modified/new encrypted file/folder, or delete the file/folder via WebDAV
6. Encrypt the metadata using metadata-key
7. Sign the metadata as described [above](#signing-the-metadata)
8. Upload encrypted metadata 
9. Unlock the folder

#### Uploading payload and metadata file (step 5 & 8)
To keep the metadata and the file in sync locking is required.
The client needs to lock the topmost encrypted (sub-)folder which needs to be changed and pass the incremented counter as header.
The lock also covers all subfolders of the locked folder.
The server checks if the incremented counter is greater than the counter of the last lock of this folder, if not it will fail with HTTP status code 412 Precondition Failed.
If the folder (or one of its parent folders) is already locked, the server responds with HTTP status code 423 Locked.
If the lock operation succeeded, the server responds with HTTP status code 200 together with a token in the response body.
In case the client lost connection after locking the folder, it can restart the operation later with another "lock" request.
In this case the client must send the token with the new lock call.
This enables the server to decide if the client is allowed to retry the upload.

After locking was successful, the client will
- upload the encrypted file
- upload the metadata file with signature as header

After both files are uploaded successfully the client will finish the operation by sending an unlock request.
All changes done while the folder is locked are only applied by the server when the folder is unlocked.

The `<folder-id>` denotes the ID of the end-to-end encrypted folder given by the WebDAV API.

To lock the folder a `POST` request to the `/lock/<folder-id>` endpoint has to be sent.
- The incremented counter has to be sent as the `X-NC-E2EE-COUNTER` HTTP header.
- To reuse an existing lock token it can be sent as the `e2e-token` parameter.
- The server returns the lock token as the `e2e-token` key of the response data.

All WebDAV requests modifying the content of a locked folder (e.g. `PUT`, `MKCOL`, `MOVE`, `COPY` or `DELETE`) have to include the lock token as the `e2e-token` HTTP header.

To update the metadata a `PUT` request to the `/meta-data/<folder-id>` endpoint has to be sent.
- The computed signature needs to be sent as header `X-NC-E2EE-SIGNATURE`.
- The current lock token has to be included as `e2e-token` header.
- The encrypted metadata JSON has to be sent as the URL-encoded `metaData` parameter.

If the folder is not locked with the given token, the server responds with HTTP status code 412 Precondition Failed.

To unlock the folder a `DELETE` request to `/lock/<folder-id>` has to be sent.
- The previously received lock token has to be sent as `e2e-token` HTTP header.
- To discard all changes done while the folder was locked, the parameter `abort` with the value `true` can be sent.
  The server then reverts the changes to the state before the folder was locked.

If unlocking fails, the client has to make sure that it retries or aborts the operation so that the folder is then again in an unlocked and consistent state.


#### Detect encrypted folder
##### Encrypted folder gets added
- WebDAV endpoint lists folder with the `{http://nextcloud.org/ns}is-encrypted` property set to `1`
  - the metadata of the folder is also available as `{http://nextcloud.org/ns}e2ee-metadata` WebDAV property
- client shows lock symbol when listing folder
- client refuses to update encryption status to false as this is not allowed.
  If server sends such an information the client has to warn the user.
- upon entering an encrypted folder the client continues with [Accessing encrypted files](#accessing-encrypted-files)

##### Encrypted folder gets deleted
If WebDAV endpoints does not list an encrypted folder anymore, the client has to check if this is a valid delete.
Therefore, the client has to request the metadata using a `GET` request to the `/meta-data/<folder-id>` OCS endpoint and validate the metadata file and check if `deleted` is set to true.
Otherwise, the client needs to display warning that the folder was maliciously deleted and refuse to delete the locally synced content.

#### Accessing encrypted files
No locking is required to read files of an encrypted folder.
If the folder is locked due to an ongoing upload, the server responds with HTTP status code 423 Locked.
The client can then present the currently stored files alongside with a warning and disable on mobile or postpone on desktop the possibility to do any file operation.
To access encrypted files the client has to do the following steps:

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

In case a file is referenced in the metadata but cannot be found on the WebDAV file system the user should be warned about this.
If the file exists locally but not on the file system the client should re-upload the file.

### Sharing encrypted folders to other users
#### Key discovery of other users
As a PKI approach for encryption is used, every certificate is issued by a central root authority.
By default, the Nextcloud server acts as a root authority and issues the certificates from the CSRs.

The clients do the following when trying to establish a trust relationship to another user:

1. Check if a certificate for the specified user ID is already downloaded (Trust On First Use (TOFU))
   1. If a certificate is available, it will be used
   2. If none is available, the client will continue at 2.
2. Query the user certificate by sending GET request to the `/public-key` endpoint and sending a JSON encoded `users` parameter containing the specified UIDs
3. If the user has not yet set up E2E and thus no public key, it will not be possible to share with the user. 
   A warning should then be shown.
4. Verify that the certificate is issued by the downloaded server public key.
   1. If yes: Use this one.
   2. If no: Show a warning that initiating an encrypted share is not possible to the user.
5. Store the user certificate locally for next operations

#### Add someone to an end-to-end encrypted folder
To create a share the following actions have to be performed:

1. The file has to be shared via the [OCS sharing](https://docs.nextcloud.com/server/latest/developer_manual/client_apis/OCS/ocs-share-api.html) API to the recipient
2. Generate a new metadata key
3. The recipient is added to the users array with
  - userId
  - certificate
4. Add/replace the new metadata-key of every user in the users-list. 
   The metadata-key is encrypted with the user's public key.
5. The SHA-256 hash of the metadata-key is added to the keyChecksum array.
6. The metadata of all subfolders is encrypted with the new metadata-key and uploaded.

#### Remove someone from an existing share
To remove someone from an existing share the following actions have to be performed:

1. The file has to be unshared via the [OCS sharing](https://docs.nextcloud.com/server/latest/developer_manual/client_apis/OCS/ocs-share-api.html) API to the recipient
2. A new metadata-key must be generated
3. The recipient is removed from the users array
4. Add/replace the new metadata-key to every user in the users-list. 
   The metadata-key is encrypted with the user's public key.
5. The SHA-256 hash of metadata key is added to keyChecksum array.
6. The metadata of all subfolders is encrypted with the new metadata-key and uploaded.

### Sharing to external users
To share end-to-end encrypted files with users without a Nextcloud account,
it is possible to create public shares with end-to-end encryption.
For this the encrypted root folder has to be shared with Nextcloud sharing flow as a link share.
Then a public- / private key pair has to be generated as described for the initial setup,
with some changes:
- For the requests to the `/public-key` and `/private-key` endpoints the `shareToken` parameter,
  with the value of the token of the created share, has to be included.
- The `CN` of the public certificate has to be set to `s:SHARE_TOKEN`,
  where `SHARE_TOKEN` has to be replaced with the token of the share.

This new "share user" has to be added just like a normal user to the metadata.
To distinguish between public share users and normal users the user id can be checked for the `s:` prefix as the colon character is not allowed in normal user ids.
When a public share user is added to the users array, the metadata version has to be set to `"2.1"`.

The generated private key is encrypted as described for the initial setup with a new generated mnemonic,
and will be stored on the server under the `s:SHARE_TOKEN` id.
The client then should provide the new mnemonic to the sharing user which has to provide this information
to the share recipient using a secure second channel.

The share recipient has to include the share token as the `X-NC-E2EE-SHARE-TOKEN` HTTP header in all OCS API requests,
e.g. to download the private key, to lock the folder or to access the metadata.
Only for adding filedrop entries the share token is sent as the `shareToken` parameter.

### Edge cases
#### Handling of complete key material loss
Right now a complete key material loss means that other users that already had a share with the user will not be able to share new encrypted folders since the protocol uses TOFU for initiating shares.

However, considering the fact that the user has a mnemonic passphrase to recover their key and any connected device (e.g. their smartphones) also has a way to recover the mnemonic we consider this an edge-case at the moment.

We are investigating how a CSR approach here could help in such edge-cases at least to allow new share again.

## Possible extensions

### Manual key verification
The clients could expose QR-codes of their public keys to make manual verification of other users' public keys possible.

### Hardware security module (HSM)
A HSM would act as trusted third party and would eliminate the Nextcloud server from the key exchange process completely.
I.e. it could replace trust on first use with a central trusted certificate authority (CA).
The CA also would make key revocation possible with a certificate revocation list CRLs or OCSP.
To implement CRLs the clients would always check if a key was revoked before they encrypt something with a given key.

## Scenarios

### Regular operations

#### move folder from subfolder into another
- /enc/folderA/test shall be moved into /enc/folderA/subfolderB/
- topmost folder is in that case folderA, so this needs to be locked and other subfolders of /enc are still accessible
- metadata of /enc/folderA and /enc/folderA/subfolderB needs to be handled correctly, e.g. with counter

- /enc/folderA/test shall be moved into /enc/folderB/
- topmost folder is in that case /enc, so this needs to be locked, thus complete encrypted directory is locked

### Attack scenarios

#### replay attack
- An attacker reverts metadata file and payload to any previous state (e.g. malicious admin).
- upon next sync at least the client with the latest sync can detect this attack by checking the counter
- there will always be at least one client that has the latest sync state (the client which issued the latest change)
- limitation: 
    - it can happen that the client with the latest sync state is offline and thus the detection will be delayed. 
      In the worst case scenario it will never be detected, if the client never syncs again
    - meanwhile other clients cannot detect the replay attack and will do file/folder operations as usual
- No encrypted data can be decrypted by this attacker 

#### removed sharee tries to re-add itself
Given a share with User A, B and C.
User C is removed by User A at a later time.
User C now tries to gain access to the share again by first adding itself via Nextcloud share API.
User C adds itself to users array of metadata file again.
User C does not know the metadata-key that was generated when user C was removed.
So if user C creates a new metadata-key to get access, the checksum of the metadata-key generated on removal is missing in keyChecksums.
User A/B can now detect the malicious attack as a hash has been removed from keyChecksums.
If user C instead keeps the encrypted metadata, user C cannot decrypt it, but the same considerations as in the next scenario apply.

#### User with valid certificate tries to add himself
In this scenario the attacker is a valid user of the Nextcloud instance and therefore has a certificate issued by the Nextcloud server or trusted CA.
Main idea of the attack:
- Attacker adds himself to the users list and waits until a new metadata key is used.
- The new metadata-key will be encrypted with the public key of the attacker

The signature on its own does not prevent this attack.
Creating the signature does not require the metadata-key and the signer is looked up in the users array,
so the attacker can create a valid signature with their own certificate after adding themselves.

The attacker cannot modify the encrypted part of the metadata, as this requires the metadata-key.
Thus the users array changed, but the counter was not increased.
Only clients that know the latest metadata are able to detect this, e.g. a newly added device cannot.

_**Note:** Detecting this scenario is not yet covered by the checks described in [Verifying the metadata](#verifying-the-metadata)._

#### Attacker deletes topmost folder and/or metadata file on server
- Attacker deletes on server either metadata file, WebDAV folder or both
- Client detects on next sync
- if metadata file is missing or corrupt, then client warns user and refuses to delete local content
- if folder is missing on WebDAV endpoint, client downloads the latest metadata file and check for deleted flag
- if deleted flag is set to true, the client accepts this as a regular folder deletion
- if metadata file and WebDAV files are missing, client warns user and refuses to delete local content

#### Attacker advertises new share as unencrypted to a new sharee instead of encrypted
- we cannot guarantee encryption status on shared folder for a new sharee, because of the TOFU assumption.
- the user is responsible to make a plausible check if folder name and context of the files/folder should be encrypted and detect such a scenario
