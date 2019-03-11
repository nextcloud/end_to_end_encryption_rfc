#include <QCoreApplication>
#include <QDebug>
#include <QLoggingCategory>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QByteArray>
#include <QRegularExpression>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/engine.h>

Q_LOGGING_CATEGORY(lcCse, "nextcloud.sync.clientsideencryption", QtInfoMsg)
Q_LOGGING_CATEGORY(lcCseDecryption, "nextcloud.e2e", QtInfoMsg)
Q_LOGGING_CATEGORY(lcCseMetadata, "nextcloud.metadata", QtInfoMsg)

QByteArray binaryJsonProperty(QJsonObject json, QString fileName) {
    return QByteArray::fromBase64(json[fileName].toString().toLatin1());
}

QByteArray deriveKeyEncryptionKey(QString& mnemonic, QByteArray& salt) {
    const int iterationCount = 1024;
    const int keyStrength = 256;
    const int keyLength = keyStrength/8;

    auto normalizedMnemonic = mnemonic.toLower().replace(QRegularExpression("\\s"), "");

    unsigned char secretKey[keyLength];
    if (1 != PKCS5_PBKDF2_HMAC_SHA1(
                normalizedMnemonic.toLocal8Bit().constData(),
                normalizedMnemonic.size(),
                (const unsigned char *)salt.constData(),
                salt.size(),
                iterationCount,
                keyLength,
                secretKey
                )) {
        qCInfo(lcCse()) << "kdf failed" << endl;
        // Error out?
    }

    return QByteArray((const char *)secretKey, keyLength);
}

QByteArray decryptPrivateKey(QJsonObject data, QString& mnemonic) {
    auto salt = binaryJsonProperty(data, "salt");
    auto nonce = binaryJsonProperty(data, "nonce");
    auto authenticationTag = binaryJsonProperty(data, "authenticationTag");
    auto encryptedKey = binaryJsonProperty(data, "encryptedKey");

    auto kek = deriveKeyEncryptionKey(mnemonic, salt);

    EVP_CIPHER_CTX *ctx;
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        return QByteArray();
    }
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    if(!EVP_DecryptInit_ex(ctx, nullptr, nullptr, (unsigned char *)kek.constData(), (unsigned char *)nonce.constData())) {
        qCInfo(lcCse()) << "Error initialising key and iv";
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    unsigned char *ptext = (unsigned char *)calloc(encryptedKey.size() + 16, sizeof(unsigned char));
    int plen;

    if(!EVP_DecryptUpdate(ctx, ptext, &plen, (unsigned char *)encryptedKey.constData(), encryptedKey.size())) {
        qCInfo(lcCse()) << "Could not decrypt";
        EVP_CIPHER_CTX_free(ctx);
        free(ptext);
        return QByteArray();
    }

    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, authenticationTag.size(), (unsigned char *)authenticationTag.constData())) {
        qCInfo(lcCse()) << "Could not set tag";
        EVP_CIPHER_CTX_free(ctx);
        free(ptext);
        return QByteArray();
    }

    int len = plen;
    if (EVP_DecryptFinal_ex(ctx, ptext + plen, &len) == 0) {
        qCInfo(lcCse()) << "Tag did not match!";
        EVP_CIPHER_CTX_free(ctx);
        free(ptext);
        return QByteArray();
    }

    QByteArray result((char *)ptext, plen);

    free(ptext);
    EVP_CIPHER_CTX_free(ctx);

    return result;
}

QJsonObject findRecipient(QByteArray certificate, QJsonArray recipients) {
    for (int i=0; i<recipients.size(); i++) {
        if (certificate == binaryJsonProperty(recipients[i].toObject(), "certificate")) {
            return recipients[i].toObject();
        }
    }
    // how to indicate, if the certificate was not found in any recipient?
}

EVP_PKEY* toPrivateEVPKey(QByteArray pkcs8Binary) {
    BIO *privateKeyBio = BIO_new(BIO_s_mem());
    BIO_write(privateKeyBio, pkcs8Binary.constData(), pkcs8Binary.size());

    return d2i_PrivateKey_bio(privateKeyBio, nullptr);
}

QByteArray unwrapMetadataKey(QByteArray privateKey, QByteArray ciphertext) {
    auto key = toPrivateEVPKey(privateKey);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, ENGINE_get_default_RSA());
    if (!ctx) {
        qCInfo(lcCseDecryption()) << "Could not create the PKEY context.";
        return {};
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        qCInfo(lcCseDecryption()) << "Could not init the decryption of the metadata";
        return {};
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        qCInfo(lcCseDecryption()) << "Error setting the encryption padding.";
        return {};
    }

    int err = EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    if (err <= 0) {
        qCInfo(lcCseDecryption()) << "Error setting OAEP SHA 256";
        return {};
    }

    err = EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());
    if (err <= 0) {
        qCInfo(lcCseDecryption()) << "Error setting MGF1 padding";
        return {};
    }

    size_t outlen = 0;
    err = EVP_PKEY_decrypt(ctx, nullptr, &outlen,  (unsigned char *)ciphertext.constData(), ciphertext.size());
    if ( err <= 0) {
        qCInfo(lcCseDecryption()) << "Could not determine the buffer length";
        return {};
    }
    qCInfo(lcCseDecryption()) << "Size of output is: " << outlen;
    qCInfo(lcCseDecryption()) << "Size of data is: " << ciphertext.size();

    unsigned char *out = (unsigned char *) OPENSSL_malloc(outlen);
    if (!out) {
        qCInfo(lcCseDecryption()) << "Could not alloc space for the decrypted metadata";
        return {};
    }

    if (EVP_PKEY_decrypt(ctx, out, &outlen, (unsigned char *)ciphertext.constData(), ciphertext.size()) <= 0) {
        qCInfo(lcCseDecryption()) << "Could not decrypt the data.";
        ERR_print_errors_fp(stdout); // This line is not printing anything.
        return {};
    }
    qCInfo(lcCseDecryption()) << "data decrypted successfully";

    const auto ret = std::string((char*) out, outlen);
    QByteArray raw((const char*) out, outlen);
    qCInfo(lcCse()) << raw;
    return raw;
}

int main(int argc, char *argv[])
{
    QString mnemonic = "quarter plate lunch sick stone height canvas key scatter trust copper labor";

    QString encryptedPrivateKeyJson = R"JSON({
                                      "encryptedKey": "dTu0SEIcdgTsOCUEDgGPGgwyJBqkWwW8MHzLOD5RAqrKbdLF1eYJm2GGKMi812V5BQl1WBeUK42xhNUmtk4sJjEvnLyYS8nbo5B2YdLQ8XOhINQvnbSLWetByAW5s78ZUpSPpfsTBD1vdPiezgTSMBaQbulhK1OdBpvbzNHjazgfv43uTilO4Xwt3JycFmI2pdpKIRhZm+8npjaUr5hfusRa0av1MjdmB3iBes0urbvSvj9jKGmKcOZwQw4w+tdmdtQZDnVOX186LefKW9f8ThdO6avIcBA8HzuDH15jodGhirHnx46KjRktvqRSaSatPsq+vmZuvcDnV7MsKKm4QE8cR80H7HPd6jhamLPbkBPsjke6QWAWO37TP5y/tSVH3LDh1d83E+TkbZ3bxB+Wr5UIzBZI5E7hOuoToos2DdcAyo6RWduCb5QDJyj9Azz1wZ2gd4++Z/AY2Juayyekd4HBk2l/8FkIiJrBOTkUdnxeS/yzHf9gYNceFsrYVu8t8ZRe/bhitUn1u8pF023dr+KknLmDyFyXp6t0IS4Cy8F+29IrmVc8m1Kn69cFVh3/7riy9+/bLflizefH3tV+T1VqAKCFMOctmZemvU7JmJ8BdorvtEMUuJuvJqwRi1wbsqFQ6QYZehxS9/c8+dDqvGEaZJFrX1SzriXB9OB5FyhlodXg0MzatFTAHbRFdNHSdPRhiEFXQCGoB4IzcaMt6mnFRSFbLqLnuyz3Bb4+INZ26wl0+uU5+2bDoey/zcoDLWIrIZsphLZbr3UYrGBgofpWgAf2iTM/1duKDDkmnrXGi0QYadtOTKpvc2YChPrQAsPGg1eTnVcAmZQpOCBJDbSJueUcRiW7e6XK+creEiUWAhX+UjhfyDq6fdbZZW0g5BTaGGxrtNPSFrZB3n8AK4yb5cbJsL9vXHQ/ksWhzWXVYX13CN+I0WURl+dVVBjF1xgF6YlSjVWy0SrGOSeify0uGwDUwIaHJIiJnpHQtzaeE/6ySDxx7j93nCokN+8jYU+lEmB0MHnKJEv3DhkmCSgQogMly5f0gqVknXJ79Y8f/PC9IbIq1kOYxwgnK9n9rzwfaAd4AjyxaXJ+4Wbytfe6EzRJut6J+BCEw0tI/AUfeI50WsV2HMyHvaRcVP0AYFdNXy8kuc7Z05+lsCVF6Q3vbcG2sHWgXDtYbPvWgOzWvZRwjLjC8QK0apn3EYpwpgCOehjmK1r3Bv5BWK4ehgYtndb7TFwnVrDyBIRYdDuocV9i31ewpRg1r83DBSEhKZR78TI15YiYeWOXBSuV4sJFqyBMss4j0bt4DjuGFStd16ej/AAyCwnPTJ72Y6enZwwwiFCfxb1B+YJw1lE3qeN+g2xW7m067mKymjLGbK3zA2G8ck3t+SHwsAe+qxgQegwt4190mSK1g/ECIBunmrCq9kbWEtfyd8G4ePRaDszFamh1mMTYJNfO8uWRUWQ37KkwL6sMqccKc2otiz+/SE4s8PypB75VkLHE+3ZmVoAxykPNAdNLP2kVhVI/WEc/f7V+w2aBb36UMfTImeKoHKk+ylUp0D9rHXGuPVPQRkLntPjJqEukW8I97HLNJHjfZha6yTXKcHgQY/PcLe+gojDb",
                                      "salt": "R8471yyuxILMr8WVnBRmDpx64igzhXY9x9h2262Dd1F1f/RCpGhR9A==",
                                      "nonce": "ylcAiZwWjnWhdy6J",
                                      "authenticationTag": "2WGigGHgD2n2daIk+OhlFQ=="
                                      })JSON";
    QJsonObject encryptedPrivateKeyData = QJsonDocument::fromJson(encryptedPrivateKeyJson.toLatin1()).object();
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
    QJsonObject metadata = QJsonDocument::fromJson(metadataJson.toLatin1()).object();
    QByteArray certificate = QByteArray::fromBase64("MIIDQzCCAfegAwIBAgIBATBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAQUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAQUAogMCASAwDzENMAsGA1UEAwwEdGVzdDAeFw0xOTAzMTExMDU4NDBaFw0xOTA0MTAxMDU4NDBaMA8xDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCO4huiznGskjF+GLJ8tf0R6SsHP50/UIu6lcrupwSeJY+sQ2wHRSMEfGQBHBMIqpFEtIWZ4L/d1+/OKdtaKlF4NiGnqJhx6Tjzl0vJPJevuYBvXUaunU3IuFloRwLgANZbe5wnMUg/+wjEYXfP15H3D+Eq1s5tX7US3+TDXchjFZGa6m33K2QQ6ocRDx3sSnzGkDrW6yxLDnVXn/hDC68YpEJ1fGkfY27HyVZ6he+SvhlFd9pJDVLZ2JkP49HrBbEywd020MjzZ44Oxrq32Zbv71Eluxsvr7L/5jH5PevKGiSQzWQgWCeR8oKEOK0Bil2UnwJtbHg2V9T9XrakmhNBAgMBAAGjQjBAMB8GA1UdIwQYMBaAFMk+BPx+d4CFe9PkJmx20lWzHh0PMB0GA1UdDgQWBBTJPgT8fneAhXvT5CZsdtJVsx4dDzBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAQUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAQUAogMCASADggEBADmh/PXTMN7933Dmj+eS4B4Gnfpd7dc37mxiMA/79KaqM5P3DlmPBYCljM19L0WUCqU0OwjiMBGFnkjf7Xjbb58p04BsJqQjrOJbdHAfiNbk5LdXtIaHylND2osHsdblKbFbZsspZr30hM7Dg7yhuQx7VEA9eLFX9d6s7IgNAaQ5lJ+ZrSoQW4i0/8eIVdWXJID40eEtTEghPo+OQaMEeBReBFfSatNoynZs2jLDbFtlRLmHXr/NmaRbr/kf/CNNc5wo2+SWHD1hAJgZR22dSb4enMNwlonIQO+YwCZ3xHdGdrKVd9SMuGHJgbhmwm07aC6nI/xMZTCkTPS3oikk+no=");

    auto privateKey = decryptPrivateKey(encryptedPrivateKeyData, mnemonic);
    auto recipient = findRecipient(certificate, metadata["recipients"].toArray());

    auto metadatakey = unwrapMetadataKey(privateKey, binaryJsonProperty(recipient, "encryptedKey"));

    //qDebug() << privateKey.toBase64() << endl;
    //qDebug() << recipient << endl;
    qDebug() << metadatakey.toHex() << endl;
}
