#include <QCoreApplication>
#include <QDebug>
#include <QLoggingCategory>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QByteArray>
#include <QRegularExpression>
#include <QFile>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include <zlib.h>

#define CHUNK_SIZE 16384

#define UNSIGNED(x) reinterpret_cast<unsigned char*>(x)
#define SIGNED(x) reinterpret_cast<char*>(x)

Q_LOGGING_CATEGORY(lcCse, "nextcloud.sync.clientsideencryption", QtInfoMsg)
Q_LOGGING_CATEGORY(lcCseDecryption, "nextcloud.e2e", QtInfoMsg)
Q_LOGGING_CATEGORY(lcCseMetadata, "nextcloud.metadata", QtInfoMsg)


bool jsonPropertyAsBytes(QJsonObject &json, QString property, QByteArray &result) {
    result = QByteArray::fromBase64(json[property].toString().toLatin1());

    return !result.isEmpty();
}

class EncryptedPrivatekeyData {
public:
    QByteArray salt;
    QByteArray nonce;
    QByteArray authenticationTag;
    QByteArray encryptedKey;

    static bool fromJson(QJsonObject &json, EncryptedPrivatekeyData &parsed) {
        if (!jsonPropertyAsBytes(json, "salt", parsed.salt)) {
            qCInfo(lcCse()) << "missing property salt";
            return false;
        }
        if (!jsonPropertyAsBytes(json, "nonce", parsed.nonce)) {
            qCInfo(lcCse()) << "missing property nonce";
            return false;
        }
        if (!jsonPropertyAsBytes(json, "authenticationTag", parsed.authenticationTag)) {
            qCInfo(lcCse()) << "missing property authenticationTag";
            return false;
        }
        if (!jsonPropertyAsBytes(json, "encryptedKey", parsed.encryptedKey)) {
            qCInfo(lcCse()) << "missing property encryptedKey";
            return false;
        }
        return true;
    }
};

class EncryptedMetadata {
public:
    QByteArray nonce;
    QByteArray authenticationTag;
    QByteArray ciphertext;

    static bool fromJson(QJsonObject &json, EncryptedMetadata &parsed) {
        if (!jsonPropertyAsBytes(json, "nonce", parsed.nonce)) {
            qCInfo(lcCse()) << "missing property nonce";
            return false;
        }
        if (!jsonPropertyAsBytes(json, "authenticationTag", parsed.authenticationTag)) {
            qCInfo(lcCse()) << "missing property authenticationTag";
            return false;
        }
        if (!jsonPropertyAsBytes(json, "ciphertext", parsed.ciphertext)) {
            qCInfo(lcCse()) << "missing property ciphertext";
            return false;
        }
        return true;
    }
};

class FileInfo {
public:
    QByteArray key;
    QByteArray nonce;
    QByteArray authenticationTag;
    QString name;
    QString mimetype;

    static bool fromJson(QJsonObject &json, FileInfo &parsed) {
        if (!jsonPropertyAsBytes(json, "nonce", parsed.nonce)) {
            qCInfo(lcCse()) << "missing property nonce";
            return false;
        }
        if (!jsonPropertyAsBytes(json, "authenticationTag", parsed.authenticationTag)) {
            qCInfo(lcCse()) << "missing property authenticationTag";
            return false;
        }
        if (!jsonPropertyAsBytes(json, "key", parsed.key)) {
            qCInfo(lcCse()) << "missing property key";
            return false;
        }
        parsed.name = json["name"].toString();
        parsed.mimetype = json["mimetype"].toString();

        return true;
    }
};

// internal?
bool gunzip(QByteArray &compressed, QByteArray &inflated) {
    int gz_code;
    z_stream gunzip;

    gunzip.zalloc = Z_NULL;
    gunzip.zfree = Z_NULL;
    gunzip.opaque = Z_NULL;

    if (Z_OK != inflateInit2(&gunzip, 16+MAX_WBITS)) {
        qDebug() << "failed to init gunzip" << endl;
        return false;
    }

    gunzip.avail_in = static_cast<unsigned int>(compressed.size());
    gunzip.next_in = UNSIGNED(compressed.data());

    char buffer[CHUNK_SIZE];
    do {
        gunzip.avail_out = CHUNK_SIZE;
        gunzip.next_out = UNSIGNED(buffer);

        gz_code = inflate(&gunzip, Z_NO_FLUSH);
        if (gz_code == Z_STREAM_ERROR) {
            qDebug() << "failed to perform gunzip" << endl;
            return false;
        }
        inflated.append(buffer, static_cast<int>(CHUNK_SIZE - gunzip.avail_out));
    } while (gunzip.avail_out == 0);
    if(gz_code != Z_STREAM_END) {
        qDebug() << "expected gunzip to be in state STREAM_END" << endl;
        return false;
    }

    return true;
}

// internal
bool deriveKeyEncryptionKey(QString &mnemonic, QByteArray &salt, QByteArray &derivedKey) {
    const int iterationCount = 1024;
    const int keyStrength = 256;
    const int keyLength = keyStrength/8;

    auto normalizedMnemonic = mnemonic
            .toLower()
            .replace(" ", "")
            .replace("\t", "")
            .replace("\r", "")
            .replace("\n", "");

    unsigned char secretKey[keyLength];
    if (!PKCS5_PBKDF2_HMAC_SHA1(
                normalizedMnemonic.toLocal8Bit().constData(),
                normalizedMnemonic.size(),
                UNSIGNED(salt.data()),
                salt.size(),
                iterationCount,
                keyLength,
                secretKey
                )) {
        qCInfo(lcCse()) << "kdf failed" << endl;
        return false;
    }

    derivedKey = QByteArray(SIGNED(secretKey), keyLength);
    return true;
}

// external
bool decryptPrivateKey(EncryptedPrivatekeyData &keyData, QString &mnemonic, QByteArray &privateKey) {
    auto encryptedKey = keyData.encryptedKey;
    auto authenticationTag = keyData.authenticationTag;

    QByteArray kek;
    if (!deriveKeyEncryptionKey(mnemonic, keyData.salt, kek)) {
        qCInfo(lcCse()) << "failed to derive key";
        return false;
    }

    EVP_CIPHER_CTX *ctx;
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        qCInfo(lcCse()) << "failed to acquire EVP context";
        return false;
    }
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
        qCInfo(lcCse()) << "failed to initialize AES-256 GCM";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if(!EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                           UNSIGNED(kek.data()),
                           UNSIGNED(keyData.nonce.data()))) {
        qCInfo(lcCse()) << "Error initialising key and nonce";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    unsigned char *ptext = static_cast<unsigned char*>(calloc(static_cast<size_t>(encryptedKey.size()), sizeof (unsigned char)));
    int plen;

    if(!EVP_DecryptUpdate(ctx, ptext, &plen,UNSIGNED(encryptedKey.data()), encryptedKey.size())) {
        qCInfo(lcCse()) << "Could not decrypt";
        EVP_CIPHER_CTX_free(ctx);
        free(ptext);
        return false;
    }

    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, authenticationTag.size(), UNSIGNED(authenticationTag.data()))) {
        qCInfo(lcCse()) << "Could not set tag";
        EVP_CIPHER_CTX_free(ctx);
        free(ptext);
        return false;
    }

    int len = plen;
    if (EVP_DecryptFinal_ex(ctx, ptext + plen, &len) == 0) {
        qCInfo(lcCse()) << "Tag did not match!";
        EVP_CIPHER_CTX_free(ctx);
        free(ptext);
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);

    privateKey = QByteArray(SIGNED(ptext), plen);
    free(ptext);

    return true;
}

// external
bool findRecipient(QByteArray &certificate, QJsonArray &recipients, QJsonObject &result) {
    for (int i=0; i<recipients.size(); i++) {
        QJsonObject recipient = recipients[i].toObject();
        QByteArray recipientCert;
        if (jsonPropertyAsBytes(recipient, "certificate", recipientCert)) {
            if (certificate == recipientCert) {
                result = recipient;
                return true;
            }
        } else {
            qCInfo(lcCse()) << "missing property 'certificate' on recipient";
        }
    }

    return false;
}

// internal
EVP_PKEY* toPrivateEVPKey(QByteArray pkcs8Binary) {
    BIO *privateKeyBio = BIO_new(BIO_s_mem());
    BIO_write(privateKeyBio, pkcs8Binary.constData(), pkcs8Binary.size());

    return d2i_PrivateKey_bio(privateKeyBio, nullptr);
}

// external
bool unwrapMetadataKey(QByteArray privateKey, QByteArray ciphertext, QByteArray &metadataKey) {
    auto key = toPrivateEVPKey(privateKey);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, ENGINE_get_default_RSA());
    if (!ctx) {
        qCInfo(lcCseDecryption()) << "Could not create the PKEY context.";
        return false;
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        qCInfo(lcCseDecryption()) << "Could not init the decryption of the metadata";
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        qCInfo(lcCseDecryption()) << "Error setting the encryption padding.";
        return false;
    }
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
    int err = EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    if (err <= 0) {
        qCInfo(lcCseDecryption()) << "Error setting OAEP SHA 256";
        return false;
    }

    err = EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());
    if (err <= 0) {
        qCInfo(lcCseDecryption()) << "Error setting MGF1 padding";
        return false;
    }
#pragma GCC diagnostic pop

    size_t outlen = 0;
    err = EVP_PKEY_decrypt(ctx, nullptr, &outlen,  UNSIGNED(ciphertext.data()), static_cast<size_t>(ciphertext.size()));
    if ( err <= 0) {
        qCInfo(lcCseDecryption()) << "Could not determine the buffer length";
        return false;
    }

    unsigned char *out = static_cast<unsigned char*>(OPENSSL_malloc(outlen));
    if (!out) {
        qCInfo(lcCseDecryption()) << "Could not alloc space for the decrypted metadata key";
        return false;
    }

    if (EVP_PKEY_decrypt(ctx,
                         out,
                         &outlen,
                         UNSIGNED(ciphertext.data()),
                         static_cast<size_t>(ciphertext.size()))
            <= 0) {
        qCInfo(lcCseDecryption()) << "Could not decrypt the data.";
        ERR_print_errors_fp(stdout);
        OPENSSL_clear_free(out, outlen);
        return false;
    }
    qCInfo(lcCseDecryption()) << "data decrypted successfully";

    metadataKey = QByteArray(SIGNED(out), static_cast<int>(outlen));
    OPENSSL_clear_free(out, outlen);

    return true;
}

// external
bool decryptMetadata(QByteArray &metadataKey, EncryptedMetadata &encryptedMetadata, QJsonObject &metadata) {
    // perform aes-128-gcm decryption

    EVP_CIPHER_CTX *ctx;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        qCInfo(lcCse()) << "Could not create context";
        return false;
    }

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr)) {
        qCInfo(lcCse()) << "Could not init cipher";
        return false;
    }

    if(!EVP_DecryptInit_ex(ctx, nullptr, nullptr, UNSIGNED(metadataKey.data()), UNSIGNED(encryptedMetadata.nonce.data()))) {
        qCInfo(lcCse()) << "Error initialising key and iv";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    size_t plainlen = static_cast<size_t>(encryptedMetadata.ciphertext.size());
    unsigned char *plaintext = static_cast<unsigned char*>(OPENSSL_malloc(plainlen));
    int plen;
    if(!EVP_DecryptUpdate(ctx, plaintext, &plen, UNSIGNED(encryptedMetadata.ciphertext.data()), encryptedMetadata.ciphertext.size())) {
        qCInfo(lcCse()) << "Could not decrypt";
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_clear_free(plaintext, plainlen);
        return false;
    }

    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, encryptedMetadata.authenticationTag.size(), UNSIGNED(encryptedMetadata.authenticationTag.data()))) {
        qCInfo(lcCse()) << "Could not set tag";
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_clear_free(plaintext, plainlen);
        return false;
    }

    int len = plen;
    if (EVP_DecryptFinal_ex(ctx, plaintext + plen, &len) == 0) {
        qCInfo(lcCse()) << "Tag did not match!";
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_clear_free(plaintext, plainlen);
        return false;
    }

    QByteArray result(SIGNED(plaintext), plen);

    OPENSSL_clear_free(plaintext, plainlen);
    EVP_CIPHER_CTX_free(ctx);

    QByteArray json{};
    if (!gunzip(result, json)) {
        qDebug() << "failed to inflate decrypted json" << endl;
        return false;
    }

    metadata = QJsonDocument::fromJson(json).object();
    return true;
}

// external
bool decryptFile(QString encryptedFilename, QString plainFilename, FileInfo &fileInfo) {
    QFile encryptedSource(encryptedFilename);
    if (!encryptedSource.open(QIODevice::ReadOnly)) {
      qCDebug(lcCse) << "Could not open input file for reading" << encryptedSource.errorString();
      return false;
    }
    QFile plainTarget(plainFilename);
    if (!plainTarget.open(QIODevice::WriteOnly)) {
      qCDebug(lcCse) << "Could not open output file for writing" << plainTarget.errorString();
      return false;
    }

    QByteArray key = fileInfo.key;
    QByteArray nonce = fileInfo.nonce;
    QByteArray authenticationTag = fileInfo.authenticationTag;

    EVP_CIPHER_CTX *ctx;

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        qCInfo(lcCse()) << "Could not create context";
        return false;
    }

    // AES-128
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr)) {
        qCInfo(lcCse()) << "Could not init AES-128 GCM cipher";
        return false;
    }

    // provide key and nonce
    if(!EVP_DecryptInit_ex(ctx, nullptr, nullptr, UNSIGNED(key.data()), UNSIGNED(nonce.data()))) {
        qCInfo(lcCse()) << "Could not set key and nonce";
        return false;
    }

    qint64 size = encryptedSource.size();


    unsigned char *out = static_cast<unsigned char*>(OPENSSL_malloc(CHUNK_SIZE));
    int len;

    while(!encryptedSource.atEnd()) {

        qint64 toRead = size - encryptedSource.pos();
        if (toRead > CHUNK_SIZE) {
            toRead = CHUNK_SIZE;
        }

        QByteArray data = encryptedSource.read(toRead);

        if (data.size() == 0) {
            qCInfo(lcCse()) << "Could not read data from file";
            return false;
        }

        if(!EVP_DecryptUpdate(ctx, out, &len, UNSIGNED(data.data()), data.size())) {
            qCInfo(lcCse()) << "Could not decrypt";
            return false;
        }

        plainTarget.write(SIGNED(out), len);
    }

    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, authenticationTag.size(), UNSIGNED(authenticationTag.data()))) {
        qCInfo(lcCse()) << "Could not set expected tag";
        return false;
    }

    if(1 != EVP_DecryptFinal_ex(ctx, out, &len)) {
        qCInfo(lcCse()) << "Could not finalize decryption (wrong tag)";
        return false;
    }

    OPENSSL_clear_free(out, CHUNK_SIZE);
    EVP_CIPHER_CTX_free(ctx);

    return true;
}

// for sample only
bool writeData(QString filename, QByteArray data) {
    QFile file(filename);
    if (!file.open(QIODevice::WriteOnly)) {
      qCDebug(lcCse) << "Could not open output file for writing" << file.errorString();
      return false;
    }

    file.write(data);
    return true;
}

// for sample only
bool cat(QString filename) {
    QFile file(filename);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
        return false;

    while (!file.atEnd()) {
        QByteArray line = file.readLine();
        qDebug() << line;
    }
    return true;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
int main(int argc, char *argv[])
#pragma GCC diagnostic pop
{
    QString mnemonic = "quarter plate lunch sick stone height canvas key scatter trust copper labor";
    QString fileId = "a5604b31c1fd43229229e1af8118d849";

    QString encryptedPrivateKeyJson = R"JSON({
                                      "encryptedKey": "dTu0SEIcdgTsOCUEDgGPGgwyJBqkWwW8MHzLOD5RAqrKbdLF1eYJm2GGKMi812V5BQl1WBeUK42xhNUmtk4sJjEvnLyYS8nbo5B2YdLQ8XOhINQvnbSLWetByAW5s78ZUpSPpfsTBD1vdPiezgTSMBaQbulhK1OdBpvbzNHjazgfv43uTilO4Xwt3JycFmI2pdpKIRhZm+8npjaUr5hfusRa0av1MjdmB3iBes0urbvSvj9jKGmKcOZwQw4w+tdmdtQZDnVOX186LefKW9f8ThdO6avIcBA8HzuDH15jodGhirHnx46KjRktvqRSaSatPsq+vmZuvcDnV7MsKKm4QE8cR80H7HPd6jhamLPbkBPsjke6QWAWO37TP5y/tSVH3LDh1d83E+TkbZ3bxB+Wr5UIzBZI5E7hOuoToos2DdcAyo6RWduCb5QDJyj9Azz1wZ2gd4++Z/AY2Juayyekd4HBk2l/8FkIiJrBOTkUdnxeS/yzHf9gYNceFsrYVu8t8ZRe/bhitUn1u8pF023dr+KknLmDyFyXp6t0IS4Cy8F+29IrmVc8m1Kn69cFVh3/7riy9+/bLflizefH3tV+T1VqAKCFMOctmZemvU7JmJ8BdorvtEMUuJuvJqwRi1wbsqFQ6QYZehxS9/c8+dDqvGEaZJFrX1SzriXB9OB5FyhlodXg0MzatFTAHbRFdNHSdPRhiEFXQCGoB4IzcaMt6mnFRSFbLqLnuyz3Bb4+INZ26wl0+uU5+2bDoey/zcoDLWIrIZsphLZbr3UYrGBgofpWgAf2iTM/1duKDDkmnrXGi0QYadtOTKpvc2YChPrQAsPGg1eTnVcAmZQpOCBJDbSJueUcRiW7e6XK+creEiUWAhX+UjhfyDq6fdbZZW0g5BTaGGxrtNPSFrZB3n8AK4yb5cbJsL9vXHQ/ksWhzWXVYX13CN+I0WURl+dVVBjF1xgF6YlSjVWy0SrGOSeify0uGwDUwIaHJIiJnpHQtzaeE/6ySDxx7j93nCokN+8jYU+lEmB0MHnKJEv3DhkmCSgQogMly5f0gqVknXJ79Y8f/PC9IbIq1kOYxwgnK9n9rzwfaAd4AjyxaXJ+4Wbytfe6EzRJut6J+BCEw0tI/AUfeI50WsV2HMyHvaRcVP0AYFdNXy8kuc7Z05+lsCVF6Q3vbcG2sHWgXDtYbPvWgOzWvZRwjLjC8QK0apn3EYpwpgCOehjmK1r3Bv5BWK4ehgYtndb7TFwnVrDyBIRYdDuocV9i31ewpRg1r83DBSEhKZR78TI15YiYeWOXBSuV4sJFqyBMss4j0bt4DjuGFStd16ej/AAyCwnPTJ72Y6enZwwwiFCfxb1B+YJw1lE3qeN+g2xW7m067mKymjLGbK3zA2G8ck3t+SHwsAe+qxgQegwt4190mSK1g/ECIBunmrCq9kbWEtfyd8G4ePRaDszFamh1mMTYJNfO8uWRUWQ37KkwL6sMqccKc2otiz+/SE4s8PypB75VkLHE+3ZmVoAxykPNAdNLP2kVhVI/WEc/f7V+w2aBb36UMfTImeKoHKk+ylUp0D9rHXGuPVPQRkLntPjJqEukW8I97HLNJHjfZha6yTXKcHgQY/PcLe+gojDb",
                                      "salt": "R8471yyuxILMr8WVnBRmDpx64igzhXY9x9h2262Dd1F1f/RCpGhR9A==",
                                      "nonce": "ylcAiZwWjnWhdy6J",
                                      "authenticationTag": "2WGigGHgD2n2daIk+OhlFQ=="
                                      })JSON";
    QString metadataJson = R"JSON({
                           "version": 1,
                           "recipients": [
                           {
                           "userId": null,
                           "certificate": "MIIDQzCCAfegAwIBAgIBATBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAQUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAQUAogMCASAwDzENMAsGA1UEAwwEdGVzdDAeFw0xOTAzMTExMDU4NDBaFw0xOTA0MTAxMDU4NDBaMA8xDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCO4huiznGskjF+GLJ8tf0R6SsHP50/UIu6lcrupwSeJY+sQ2wHRSMEfGQBHBMIqpFEtIWZ4L/d1+/OKdtaKlF4NiGnqJhx6Tjzl0vJPJevuYBvXUaunU3IuFloRwLgANZbe5wnMUg/+wjEYXfP15H3D+Eq1s5tX7US3+TDXchjFZGa6m33K2QQ6ocRDx3sSnzGkDrW6yxLDnVXn/hDC68YpEJ1fGkfY27HyVZ6he+SvhlFd9pJDVLZ2JkP49HrBbEywd020MjzZ44Oxrq32Zbv71Eluxsvr7L/5jH5PevKGiSQzWQgWCeR8oKEOK0Bil2UnwJtbHg2V9T9XrakmhNBAgMBAAGjQjBAMB8GA1UdIwQYMBaAFMk+BPx+d4CFe9PkJmx20lWzHh0PMB0GA1UdDgQWBBTJPgT8fneAhXvT5CZsdtJVsx4dDzBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAQUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAQUAogMCASADggEBADmh/PXTMN7933Dmj+eS4B4Gnfpd7dc37mxiMA/79KaqM5P3DlmPBYCljM19L0WUCqU0OwjiMBGFnkjf7Xjbb58p04BsJqQjrOJbdHAfiNbk5LdXtIaHylND2osHsdblKbFbZsspZr30hM7Dg7yhuQx7VEA9eLFX9d6s7IgNAaQ5lJ+ZrSoQW4i0/8eIVdWXJID40eEtTEghPo+OQaMEeBReBFfSatNoynZs2jLDbFtlRLmHXr/NmaRbr/kf/CNNc5wo2+SWHD1hAJgZR22dSb4enMNwlonIQO+YwCZ3xHdGdrKVd9SMuGHJgbhmwm07aC6nI/xMZTCkTPS3oikk+no=",
                           "encryptedKey": "AUkr5IGhCzCgU8ALOBkUK4TiavbWHXR++ukia6Jpdpwb6OAlODK6xfMLKCetEbdkhAot5TXThLmAq1YkZtVQGY/Q1YpfYyfkfyHUUINSHuJIFiVAuKkv8IwRnDH+pypwLwj9tucKPH8qSbGf6q5eW79USmr5zCAamsdIMLkiMyirWwfI633nPxgVXYsuwDwSNI2dBIwqs4EXOZ12DKjyDmg3Lq0/LwTAMCpa4jdGPQkTYedhFrbgxQU4WkJfxvDVUA16XBkln+5urhcJlXDFzbkJhnL0hUisMxSBW/+TUvfEr/r+Hx0FfH1xuHccg6ovmFC6i1QUPl5a1Gt4MWeCbg=="
                           }
                           ],
                           "metadata": {
                           "ciphertext": "h+O0MXCJgzscKAj69cfcuSSD2UWBR3NdFN/H3MMfHuuVY+QjqjVilIyAD5wNzblDSdV3WPeAKsgXIwzyT1VFO1FPrBEiXggodqBf9WO9+O9OJfRMyI209tja5L/BnotfIn6omeV7XPsNbU6gnGk5Co6o5Zx4xFEf39M1JNmSxsfsv6k0BUPn18C2bIVuQjQxXOJUpGQFrXD5yeWLB8J6zAV533RFhvG1+xoLH0e/5QEuslfCZubiA5JjcDrNyWnnBgu5Fu6lzivIqyE4WWQBXG/oYLHnBCJ/pZX2sZgtlcy9s1u1ADVP73KRGg==",
                           "nonce": "8bkbBKCiXTQRRnRc",
                           "authenticationTag": "LtT8gx9DPVoAS8IismTvbA=="
                           }
                           })JSON";
    QByteArray encryptedFiledata = QByteArray::fromBase64("t4VeL+IQiiNWHinULQ==");

    QJsonObject encryptedPrivateKeyData = QJsonDocument::fromJson(encryptedPrivateKeyJson.toLatin1()).object();
    QJsonObject metadata = QJsonDocument::fromJson(metadataJson.toLatin1()).object();
    QByteArray certificate = QByteArray::fromBase64("MIIDQzCCAfegAwIBAgIBATBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAQUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAQUAogMCASAwDzENMAsGA1UEAwwEdGVzdDAeFw0xOTAzMTExMDU4NDBaFw0xOTA0MTAxMDU4NDBaMA8xDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCO4huiznGskjF+GLJ8tf0R6SsHP50/UIu6lcrupwSeJY+sQ2wHRSMEfGQBHBMIqpFEtIWZ4L/d1+/OKdtaKlF4NiGnqJhx6Tjzl0vJPJevuYBvXUaunU3IuFloRwLgANZbe5wnMUg/+wjEYXfP15H3D+Eq1s5tX7US3+TDXchjFZGa6m33K2QQ6ocRDx3sSnzGkDrW6yxLDnVXn/hDC68YpEJ1fGkfY27HyVZ6he+SvhlFd9pJDVLZ2JkP49HrBbEywd020MjzZ44Oxrq32Zbv71Eluxsvr7L/5jH5PevKGiSQzWQgWCeR8oKEOK0Bil2UnwJtbHg2V9T9XrakmhNBAgMBAAGjQjBAMB8GA1UdIwQYMBaAFMk+BPx+d4CFe9PkJmx20lWzHh0PMB0GA1UdDgQWBBTJPgT8fneAhXvT5CZsdtJVsx4dDzBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAQUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAQUAogMCASADggEBADmh/PXTMN7933Dmj+eS4B4Gnfpd7dc37mxiMA/79KaqM5P3DlmPBYCljM19L0WUCqU0OwjiMBGFnkjf7Xjbb58p04BsJqQjrOJbdHAfiNbk5LdXtIaHylND2osHsdblKbFbZsspZr30hM7Dg7yhuQx7VEA9eLFX9d6s7IgNAaQ5lJ+ZrSoQW4i0/8eIVdWXJID40eEtTEghPo+OQaMEeBReBFfSatNoynZs2jLDbFtlRLmHXr/NmaRbr/kf/CNNc5wo2+SWHD1hAJgZR22dSb4enMNwlonIQO+YwCZ3xHdGdrKVd9SMuGHJgbhmwm07aC6nI/xMZTCkTPS3oikk+no=");
    QJsonArray recipients = metadata["recipients"].toArray();

    EncryptedPrivatekeyData privatekeyData;
    if (!EncryptedPrivatekeyData::fromJson(encryptedPrivateKeyData, privatekeyData)) {
        qDebug() << "failed to parse encrypted private key data" << endl;
        return 1;
    }

    QByteArray privateKey;
    if (!decryptPrivateKey(privatekeyData, mnemonic, privateKey)) {
        qDebug() << "failed to decrypt private key" << endl;
        return 1;
    }
    QJsonObject recipient;
    if (!findRecipient(certificate, recipients, recipient)) {
        qDebug() << "not encrypted for me" << endl;
        return 1;
    }

    QByteArray encryptedMetadataKey;
    if (!jsonPropertyAsBytes(recipient, "encryptedKey", encryptedMetadataKey)) {
        qDebug() << "missing property 'encryptedKey'";
        return 1;
    }

    QByteArray metadatakey;
    if (!unwrapMetadataKey(privateKey, encryptedMetadataKey, metadatakey)) {
        qDebug() << "failed to decrypt metadata key";
        return 1;
    }

    QJsonObject encryptedMetadataJson = metadata["metadata"].toObject();
    EncryptedMetadata encryptedMetadata;
    if (!EncryptedMetadata::fromJson(encryptedMetadataJson, encryptedMetadata)) {
        qDebug() << "failed to parse encrypted metadata json" << endl;
        return 1;
    }
    QJsonObject plainMetadata;
    if (!decryptMetadata(metadatakey, encryptedMetadata, plainMetadata)) {
        qDebug() << "failed to decrypt metadata" << endl;
        return 1;
    }

    QJsonObject fileInfoJson = plainMetadata["files"].toObject()[fileId].toObject();
    FileInfo fileInfo;
    if (!FileInfo::fromJson(fileInfoJson, fileInfo)) {
        qDebug() << "failed to parse file info json" << endl;
        return 1;
    }

    writeData("/tmp/a5604b31c1fd43229229e1af8118d849", encryptedFiledata);

    decryptFile("/tmp/a5604b31c1fd43229229e1af8118d849", "/tmp/plain.txt", fileInfo);

    if (!cat("/tmp/plain.txt")) {
        qDebug() << "failed to dump plaintext content";
        return 1;
    }
}
