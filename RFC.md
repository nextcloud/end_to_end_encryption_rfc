# Nextcloud end-to-end encryption

* [Introduction](#Introduction)
* [Protocol design goals](#Protocol-design-goals)
    * [Usage of widely available and tested libraries for crypto primitives](#Usage-of-widely-available-and-tested-libraries-for-crypto-primitives)
    * [Sharing functionality](#Sharing-functionality)
    * [Optional central data recovery](#Optional-central-data-recovery)
    * [Simple multi-device management](#Simple-multi-device-management)
    * [Simple authenticated key exchange](#Simple-authenticated-key-exchange)
    * [Support for HSM](#Support-for-HSM)
    * [Versioning](#Versioning)
* [Accepted feature loss](#Accepted-feature-loss)
* [Security goals](#Security-goals)
    * [Attacker model](#Attacker-model)
    * [Goals](#Goals)
* [Technical implementation](#Technical-implementation)
    * [Terminology](#Terminology)
    * [Adding an end-to-end encrypted device](#Adding-an-end-to-end-encrypted-device)
        * [Initial device](#Initial-device)
        * [Further devices](#Further-devices)
    * [Creating an end-to-end encrypted folder](#Creating-an-end-to-end-encrypted-folder)
        * [Mark folder as end-to-end encrypted](#Mark-folder-as-end-to-end-encrypted)
        * [Create metadata file](#Create-metadata-file)
    * [Modifying and accessing content of an end-to-end encrypted folder](#Modifying-and-accessing-content-of-an-end-to-end-encrypted-folder)
        * [Update metadata file](#Update-metadata-file)
        * [Modifying content of end-to-end encrypted folders](#Modifying-content-of-end-to-end-encrypted-folders)
        * [Accessing encrypted files](#Accessing-encrypted-files)
    * [Sharing encrypted folders to other users](#Sharing-encrypted-folders-to-other-users)
        * [Key discovery of other users](#Key-discovery-of-other-users)
        * [Add someone to an end-to-end encrypted folder](#Add-someone-to-an-end-to-end-encrypted-folder)
        * [Remove someone from an existing share](#Remove-someone-from-an-existing-share)
    * [Edgecases](#Edgecases)
        * [Handling of complete key material loss](#Handling-of-complete-key-material-loss)
* [Possible extensions](#Possible-extensions)
    * [Manual key verification](#Manual-key-verification)
    * [Hardware security module (HSM)](#Hardware-security-module-HSM)
    * [Metadata JSON arrays](#Metadata-JSON-arrays)


## Introduction
With the announcement of the Nextcloud end-to-end encryption techpreview, we would like to invite you to scrutinize our source code and cryptographic approach.

Please note that end-to-end encryption feature is a work-in-progress and this document may describe functionalities or approaches not yet implemented in our testing releases. This document is meant as authoritative implementation guideline for our clients. 
For the sake of having smaller and incremental steps towards the final implementation we are going to continuously release updated builds of our clients.

We are looking forward to your input to refine our approach towards client side encryption. In addition, we will also make sure to validate our approach on-time by external cryptographic experts.

## Protocol design goals
The end-to-end encryption has to fulfill the following business and technical criteria.

### Usage of widely available and tested libraries for crypto primitives
We believe that for security-sensitive functionalities relying on existing and proven libraries is an essential requirement. Thus we require that:

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

### Optional central data recovery
While End-to-End encryption is meant to prevent access to data for other parties the reality is: People may lose their encryption keys.

While in an home user environment this may be acceptable, in an enterprise this can have grave implications.
Thus an optional central data recovery has to be available offering the following capabilities:

* Central recovery key per instance can be generated
* Central recovery key must not be stored on the instance and can be safely exported (e.g. to be stored in a physical vault)
* All data will also be encrypted to the central recovery key when enabled
* Users must be prominently warned in the UI of their clients if a central data recovery key is enabled
* When a central data recovery key is enabled the existing end-to-end encrypted folders must not be affected

### Simple multi-device management
Access to encrypted data should easily be possible from any device the end-user owns, this includes all mobile devices as well as desktop devices.

Thus:
* Sharing keys between existing devices must be frictionless
* Newly added devices should have access to all previously encrypted data

### Simple authenticated key exchange
Key exchange is a key problem of any cryptographic system. On one hand one wants to ensure that the key of the participating parties is authentic. On the other hand, manual comparisons of fingerprints are cumbersome and rarely something that regular users can be bothered to do.

A secure and yet simple system has to implement the following properties:
* Key exchange between parties should be frictionless
* Exchanged keys should be auditable

### Support for HSM
To fulfill enterprise security requirements it should be possible that key material is generated by a hardware security module. Thus offering strong authentication, tampering resistance and a complete audit trail.

### Versioning
The protocol has to support versioning in case of future changes in the metadata or cryptographic handling.

## Accepted feature loss
Since the data is not accessible to the server and to simplify the implementation a loss of the following features is acceptable:

* Server-Side trash bin
* Server-Side versioning
* Server-Side search
* Server-Side previews
* Access to folders via web interface
* Sharing to groups
* Sharing at the level of individual files

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

* Access to ciphertext must not leak file content nor file names.
   * Leaking the number of files in an encrypted folders is an accepted risk.
   * Leaking the name of the encrypted folder and the name of sub-folders is an accepted risk.
* Once a user has been removed from an encrypted folder they should have no relevant key material to decrypt files updated or created in the future
* **Confidentiality**: No one, except the legitimate recipients, must have access to the encrypted documents.
* **Integrity**: Even with writable access to the ciphertext one should not be able to tamper with the data.
    In case an encrypted referenced file is deleted from the file system but still found in the metadata a warning should be displayed to the user.
* **Authentication**: all changes (uploading new files, changing existing, removing existing files) to an end-to-end encrypted folder must only be made by a user who is part of the (shared) folder.

## Technical implementation
The encryption is based upon an asymmetric cryptographic system. Every user has exactly one private and public key pair. The following steps will walk through the current technical implementation of the encryption.

### Terminology
* Device: a device can be anything able to run one of our supported clients.
* file-key: the actual key used to encrypt the file
* files-array: associative array mapping random identifiers names to the (encrypted) metadata of the file
* sharing array: associative array mapping usernames to their respective public keys. Used to list the users of a shared and encrypted folder
* metadata-key: key used to encrypt the metadata of file, the file-key and the sharing array
* metadata-key array: associative array mapping and index to a metadata-key

### Adding an end-to-end encrypted device
As a first step a device has to be added to an account.
Depending on whether an end-to-end encrypted device already has been added to an account, the device will have to create new key material or use existing key material.

To check whether a certificate has already been issued or not the `/ocs/v2.php/apps/end_to_end_encryption/api/v1/public-key` endpoint should be used. In addition, the client has to download the server’s public certificate from `/ocs/v2.php/apps/end_to_end_encryption/api/v1/server-key` and use this to verify the certificate chain in all future operations.

#### Initial device
When a device is initially added to an account the device has to generate all relevant key material for the user account and provision those on the server. 

First, the client has to generate the relevant key material:

1. Client has to generate a new X.509 certificate request and private key.
   1. CN of X.509 certificate must be set to the currently logged-in User ID
2. Client uploads the X.509 certificate request to the server by sending the certificate request URL encoded as parameter `csr` to `/ocs/v2.php/apps/end_to_end_encryption/api/v1/public-key`.
3. Server issues a certificate if the CN matches the current user ID.
4. Server returns the issued certificate.
5. Client stores the private and the certificate in the keychain of the device.

In a second step, the private key will be stored encrypted on the server to simplify the addition of further devices:

1. Client generates a 12 word long mnemonic from the english BIP-0039 word list. The word list contains 2048 words, thus resulting in 2048^12 possible key combinations.
2. Client encrypts the private key using AES/GCM/NoPadding as cipher (256 bit key size) and uses PBKDF2WithHmacSHA1 as key derivation, as password the in step 1 generated mnemonic is used. The needed salt and initizialization vector is appended to the cipher text with base 64 encoded "|":  encryptedAndEncryptedBytes + "fA==" + encodedIV + "fA==" + encodedSalt
3. Client uploads the encrypted X.509 private key to the server by sending the encrypted private key URL encoded as parameter `privateKey` to `/ocs/v2.php/apps/end_to_end_encryption/api/v1/private-key`. 
4. The mnemonic is displayed to the user and the user is asked to store a copy in a secure place. For convenient reasons the mnemonic can be displayed with whitespaces, but the string for encrypting/decrypting must have no whitespaces and be lowercase.
5. The mnemonic is stored in the keychain of the device.

In case a user loses their device they can easily recover by using the mnemonic passphrase. The mnemonic passphrase can also be shown in the client settings in case the user forgets their mnemonic. Displaying the mnemonic requires the user to enter their PIN/fingerprint again on mobile devices.

#### Further devices
In case a certificate exists already for the user the client has to download the existing private key. This is done the following way:

1. Client downloads private key from the `/ocs/v2.php/apps/end_to_end_encryption/api/v1/private-key` endpoint.
2. Client asks the user for the mnemonic and decrypts the private key using AES/GCM/NoPadding as cipher (256 bit key size) and PBKDF2WithHmacSHA1 as key derivation. 
3. Client checks if private key belongs to previously downloaded public certificate
4. Client stores the private key in the keychain of the device.
5. Client stores the mnemonic in the keychain of the device.

### Creating an end-to-end encrypted folder
To create an end-to-end encrypted folders multiple steps have to be performed. First of all, data access to such folders happens via our regular WebDAV API available at `/remote.php/dav/$userId/files`.

#### Mark folder as end-to-end encrypted
After creating a folder via WebDAV the folder has to be flagged as end-to-end encrypted, this can be performed by sending a PUT request to `/ocs/v2.php/apps/end_to_end_encryption/api/v1/encrypted/<folder-id>` where `<folder-id>` has to be the folder ID indicated by our WebDAV API.

Once this flag has been set the folder will not be accessible anymore via web and also not displayed to regular DAV clients. Only empty folders can be marked as end-to-end encrypted.

#### Create metadata file
Every folder contains a metadata file containing the following information:

* Metadata of files (filename, mimetype, …)
* Access list to the folder
* Key material for files in the folder

The metadata is a JSON document with the following structure depicted below.
We use a notation with inline comments (`//`) for better readability.
Note that comments are not available in standalone JSON and only used here for better understanding.

The `metadata->metadataKeys` elements are encrypted with the recipients public keys and the values are used to encrypt the single file metadata elements.

In case the central data recovery key is enabled the metadata will also be encrypted with the servers central data recovery key.
Clients must show a prominent warning to the users for such scenarios.

The only unencrypted elements in the JSON document is the version of the metadata file.
All other information is encrypted either with users' public keys or the actual metadata-keys.

```
{
    // Metadata about the share
    "metadata": {
        // The metadata-key array.
        // Every metadata-key is encrypted with every public key of users that have access to the share.
        // It is generated by the client on first upload.
        // If a recipient has been removed from a share a new metadata-key will be generated and clients.
        // always uses the newest key.
        // Encryption algorithm: RSA/ECB/OAEPWithSHA-256AndMGF1Padding
        "metadataKeys": {
            "0": "OLDESTMETADATAKEY",
            "1": "…",
            "2": "NEWESTMETADATAKEY"
        },
        // The sharing array.
        // The following blob contains the reference to all keys that have access to the share.
        // Encrypted (symmetrically) with the latest metadata-key.
        // Encryption algorithm: AES/GCM/NoPadding (128 bit key size) with metadata-key from above.
        "sharing": {
            // Name of recipients as well as public keys of the recipients
            "recipient": {
                "recipient1@example.com": "PUBLIC KEY",
                "recipient2@example.com": "PUBLIC KEY"
            },

            // base64 encoded signature (see next section)
            "signature": "base64(signature)",
            "signedBy": "recipient1@example.com"
        },
        // The protocol version
        "version": 1
    },
    // The files-array
    "files": {
        // Following object refers to the encrypted file "ia7OEEEyXMoRa1QWQk8r" on the filesystem.
        // "ia7OEEEyXMoRa1QWQk8r" is the random identifier used to hide the actual filename.
        "ia7OEEEyXMoRa1QWQk8r": {
            // Metadata of the file.
            // Encrypted with the metadata-key listed in the metadataKey attribute.
            // The IV is appended to the blob:
            //      <encrypted metadata + authentication tag> + "fA==" + <IV>
            // Encryption algorithm: AES/GCM/NoPadding (128 bit key size)
            "encrypted": {
                // The file-key
                "key": "jtboLmgGR1OQf2uneqCVHpklQLlIwWL5TXAQ0keK",
                // Unencrypted file name
                "filename": "/foo/test.txt",
                // Mimetype, if unknown use "application/octet-stream"
                "mimetype": "plain/text",
                // Which encryption method version was used? For updating in the future.
                "version": 1
            },
            // Initialization vector used to encrypt or decrypt the file
            "initializationVector": "+mHu52HyZq+pAAIN",
            // The (GCM) authentication tag of the file
            "authenticationTag": "AHu+82ldTZ5NjDY4Qdpo4w==",
            // The index of the metadata-key used to encrypt/decrypt the "encrypted" element
            "metadataKey": 1
        }
    }
}
```

The metadata has to be created by sending a POST request to `/ocs/v2.php/apps/end_to_end_encryption/api/v1/meta-data/<folder-id>`, where `<folder-id>` has to be the folder ID indicated by our WebDAV API. The POST parameter `metaData` with the encrypted metadata has to be used.

### Signing the metadata

For the security of the protocol it is important that the plaintext of the metadata-key is signed, not the ciphertext.
All metadata-keys and their associated index as well as all recipients and all file identifiers and used metadata-keys must be signed.

The `encrypted`, `initizializationVector`, `authenticationTag` elements of a `file` element do not need to be signed, because they are protected by the authentication tags of the AES+GCM authenticated encryption.
It is therefore sufficient to sign which metadata-key is used to encrypt/decrypt the `encrypted` element.
Signing only the associative array which maps file IDs to metadata-key indices avoids decryption of all `encrypted` elements on every single request.

Problem: signed data must serialize to the same byte representation on all supported platforms, otherwise signature verification fails.
We therefore write data to a byte stream in defined order with the following rules:
* Associative arrays are sorted lexicographically by the key-value
* Strings are written without null-byte

Following schema defines the format of signed data.
The `{...}*`-notation denotes the sorted associative arrays.
A Java reference implementation is available in the [c14n](c14n) folder.

```
[
    int32(protocolversion),
    {int64(metadatakey_index),decrypted_metadata_key}*
    {str_utf8(recipient_name),recipient_key}*,
    {str_utf8(fileid),int64(metadatakey_index)}*
]
```

The resulting byte array is passed to the `SHA256withRSA` signature scheme.
The resulting signature bytes are base64 encoded and saved to the `signature` element before encrypting the metadata JSON.
The signer's username is saved in the `signedBy` element.

<!-- description of alternative c14n methods. The JSON based c14n would also allow de-serialization, which is not necessary (yet).

Following data must be signed. The base64url function denotes base64 encoding using the URL and filename safe alphabet as defined in [RFC 4648](https://tools.ietf.org/html/rfc4648#page-7).

```json
{
    "files": {
        "fileid1": "int(metadataKeyIndex)",
        "fileid2": "int(metadataKeyIndex)"
    },
    "metadatakeys": {
        "0": "base64url(decrypted_metadatakey0)",
        "1": "base64url(decrypted_metadatakey1)",
        ...
    },
    "protocolversion": 0,
    "recipients": {
        "user0": "base64url(publickey0)",
        "user1": "base64url(publickey1)"
    }
}
```

Problem: signed data must serialize to the same byte representation on all supported platforms, otherwise signature verification fails.
We use a JSON canonicalization algorithm to solve this issue.
The canonicalization is inspired by the [JCS](https://tools.ietf.org/html/draft-rundgren-json-canonicalization-scheme-01) draft and [Keybase's canonical packings](https://keybase.io/docs/api/1.0/canonical_packings#json).

* Within a given map, keys cannot be repeated.
* Keys are ordered lexicographically, sorted with case-sensitiviy.
* Keynames must be quoted with double quotes.
* No whitespace can be used in stringification output
* All characters must be in the ASCII range `[0x20,0x7e]`.
* All strings must use the minimal length encoding. For example, `A` and not `\u0041`.

Two alternative canonicalization methods are still being discussed.
1. Instead of JSON, we could use XML, where standardized canonicalization mechanisms already exist (See [canonical XML](https://www.w3.org/TR/xml-c14n/))
2. Since we do not need de-serialization capabilities a simple mechanism could be developed from scratch.
-->

### Modifying and accessing content of an end-to-end encrypted folder
In general, clients need to perform two steps to modify the content of an end-to-end encrypted folder.
Firstly, clients upload, modify or delete the actual files via the WebDAV API and secondly modify the metadata JSON accordingly.

#### Update metadata file
To keep the metadata and the file in sync locking is required.
The client needs to lock the encrypted folder.
If the lock operation succeeded the server responds with HTTP status code 200 together with a token in the response body.
In case the client lost connection after locking the folder, it can restart the operation later with another "lock" request.
In this case the client should send the token with the new lock call.
This enables the server to decide if the client is allowed to retry the upload.

After locking was successful, the client will upload the encrypted file and afterwards the metadata file.
After both files are uploaded successfully the client will finish the operation by sending an unlock request.

The `<folder-id>` denotes the ID of the end-to-end encrypted folder given by the WebDAV API.

To lock the folder a POST request to `/ocs/v2.php/apps/end_to_end_encryption/api/v1/lock/<folder-id>` has to be sent.
To add an existing lock token it can be sent as `token` parameter.

To update the metadata a PUT request to `/ocs/v2.php/apps/end_to_end_encryption/api/v1/meta-data/<folder-id>` has to be sent.
The request requires following two parameters:
* The `token` contains the current lock token
* The `metadata` contains the encrypted metadata JSON.

To unlock the folder a DELETE request to `/ocs/v2.php/apps/end_to_end_encryption/api/v1/lock/<folder-id>` has to be sent.
The previously received lock token has to be sent as `token` parameter.

#### Modifying content of end-to-end encrypted folders
The following steps are required to create, update, delete files of an end-to-end encrypted folder.
1. Lock folder
2. Check for changes in the encrypted folder. If not current, get latest metadata file.
3. Decrypt the metadata file
4. Check decrypted metadata-keys against previous version of the metadata-keys array.
    * Check that new metadata-keys are always appended to the array.
    * All metadata-keys of a previous version must be part of the new version at the same indices.
    * If these checks fail, abort and notify user
5. Check that the sharing array is encrypted with the latest metadata-key, otherwise abort and notify user
6. Check the signature of the metadata as described [above](#signing-the-metadata)
7. Perform specific steps to create/update/delete files
    * Create new files:
        1. Generate a new 128-bit encryption key for the file and encrypt it using AES/GCM/NoPadding.
        2. Create new random identifier by generating a random UUID and removing the dash (`-`). The identifier must follow `/^[0-9a-fA-F]{32}$/`
        3. Add new file to the files array in the metadata file
    * Update existing files:
        1. Generate a new 128-bit encryption key for the file and encrypt it using AES/GCM/NoPadding.
        2. Update the file in the files array of the metadata
        3. Use the existing random identifier for the encrypted file when uploading it via WebDAV
    * Delete files:
        1. Remove the corresponding entry from the files array
8. Upload modified/new encrypted file, or delete the file via WebDAV
9. Sign the metadata as described [above](#signing-the-metadata)
10. Encrypt the metadata using the latest metadata-key
11. Upload encrypted metadata
12. Unlock the folder

#### Accessing encrypted files
No locking is required to read files of an encrypted folder.
To access encrypted files the client has to do the following steps:

1. Check for changes in the encrypted folder. If not current, get latest metadata file.
2. Decrypt the metadata file
3. Check that the sharing array is encrypted with the latest metadata-key, otherwise abort and notify user
4. Loop over “files” array and decrypt the array with the newest metadata-key
5. Download the referenced files using WebDAV and decrypt using AES/GCM/NoPadding (128bit) and using the referenced file-keys in the file array.

In case a file is referenced in the metadata but cannot be found on the WebDAV file system the user should be warned about this. If the file exists locally but not on the file system the client should reupload the file.

### Sharing encrypted folders to other users
#### Key discovery of other users
As a PKI approach for encryption is used every certificate is issued by a central root authority. By default the Nextcloud server acts as a Root Authority and issues the certificates from the CSRs.

The clients do the following when trying to establish a trust relationship to another user:

1. Check if a certificate for the specified User ID is already downloaded (Trust On First Use (TOFU))
   1. If an certificate is available this one will be used
   2. If none is available the client will continue at 2.
2. Query the user certificates by sending  GET request to the `/ocs/v2.php/apps/end_to_end_encryption/api/v1/public-key`  endpoint and sending a JSON encoded `users` parameter containing the specified UIDs
3. Verify if the certificate is issued by the downloaded server public key.
4. 1. If yes: Use this one.
   2. If no: Show a warning that initiating an encrypted share is not possible to the user.
5. Store the user certificate locally for next TOFU operations


#### Add someone to an end-to-end encrypted folder
To create a share the following actions have to be performed:

1. The file has to be shared via the [OCS](https://docs.nextcloud.com/server/13/developer_manual/core/ocs-share-api.html) sharing API to the recipient
2. The metadata-keys must be encrypted to the recipient public key
3. The recipient is added to the “sharing” array

#### Remove someone from an existing share
To remove someone from an existing share the following actions have to be performed:

1. The file has to be unshared via the [OCS](https://docs.nextcloud.com/server/13/developer_manual/core/ocs-share-api.html) sharing API to the recipient
2. A new metadata-key must be generated
3. The recipient is removed from the “sharing” array
4. The metadata-key array must be re-encrypted to everyone except the recipient

All clients must always check that the sharing array is encrypted with the latest metadata-key.
This is necessary to detect when a removed user tries to maliciously modify a shared end-to-end encrypted folder.

### Edgecases
#### Handling of complete key material loss
Right now a complete key material loss means that other users that already had a share with the user will not be able to share new encrypted folders since the protocol uses TOFU for initiating shares.

However, considering the fact that the user has a mnemonic passphrase to recover their key and any connected device (e.g. their smartphones) also has a way to recover the mnemonic we consider this an edge-case at the moment.

We are investigating how a CSR approach here could help in such edge-cases at least to allow new share again. We do however encourage users to make sure to not lose access to all their devices as well as their recovery mnemonic at the same time.

## Possible extensions

### Manual key verification
The clients could expose QR-codes of their public keys to make manual verification of other users' public keys possible.

### Hardware security module (HSM)
A HSM would act as trusted third party and would eliminate the Nextcloud server from the key exchange process completely.
I.e. it could replace trust on first use with a central trusted certificate authority (CA).
The CA also would make key revocation possible with a certificate revocation list CRLs.
To implement CRLs the clients would always check if a key was revoked before they encrypt something with a given key.

### Metadata JSON arrays
In case the metadata JSON format has to be adjusted in a later version and actual JSON arrays are used following should be taken into account:
The encrypted JSON array elements should just be encrypted as simple string element.
This means that `foo => [bar, foo]` should become `foo => ciphertext` and the clients are responsible for decoding this `ciphertext` in a proper array again.
