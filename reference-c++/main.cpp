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
                                      "encryptedKey" : "uLWMU9GNO8pRz+8IcDAeh8i37mmsE8M3Ctf2WNKPZPwe9U3xWLMvXAsYzkTMqFj8vBya8XcpvE7hOqHlDUwPCaxEFBeHFmSbyj/+lcs+TwOSJGlaTGXF/j3rq41Q0BDEYlT56DemaqgayYHIEN3RrL5axJSRCdWq9grkiKLNKWsCKc6YdAc1r5RMD5jNY1rNxJr+J4quEZl2GkIvdtbxEDWpsPqWGhP5/wDkb8vr6M5cVxqr6nSgoN0bCPfP2yfNUMCCKbvDZ5sxXh+CtGK2N49dIkMlWlB8avt0lxUo9mP9rckDxmXMxV5z0naiV33Dm1Q3cq6pBJwtW8MCFJekc2HkVpZKLRLk5RBpaxRCJp+hwdPj9M2IT3C73MVxhox1TmAnbHhmR2YpJW6JJRNM4vDsgVG4+HEmpwzo2adMfSKJDCa2rOFy1UhqL8jzI/RabM9YTIAN5LFyBggkooTNrO7UbNmwShb0QCx85XcO6vOcD5J8F+KpTv/snXjjjwxRlctoVnxK8Rs1E4C8MQhNXcSlaeMC9/pogtghV4EBmEqjDP8k+uarUzs3NtZ+RdnLlVGGn0azCFlUArTkCimZEl8wZNsvTYHxWZezFbjaMfHOc6WVjR34U281g7cYmz/Vy506oB9mwXaqp6JQ1IhGm0+SabPMzHz+wdU+WhuI20R7dFaICNIpCTgvuYerzqXbtHaw9pV5KZaAMZMxJWnghbnhbqE/g3gpfC0FaQtGEHMLqfKmBVGGgtPCgKkF2D7wUknxFqggXTcnTBL07v2ogASR/WW4X6u+ciG3qvmO2lRcH/G0dCY1PT4dDCZBadJc/Sveo91a/15oVTPIDAPBl+tKyKeTbq1Lc5vjzKXkeFuQAkwwCsrEFX+SJIPjWhjEt1D3LLqX3Loa3SQ3r0ROfAYO9ncoxEEhxX8Vt6lDE4f+XTlyd3//rkc0An542Tb5Gl49KX5TTVZJUqkGz0XIMYTXo4PPTQMmXx1czxmHeQOBsaMt1sV90EeWjN7zFYRc61I/3z28S+eqNXXZom0DxOuv2MQDrtAyZP3of69wyCafQ0QsadJ8+HM5d5EbTMVHjvDxTn46onh4S6pePDr2B89AIoy/WMqFAqN8uJqwrfhzCtStHyG5dgWpEd2WsCMRlx2MwoDjHTpo9JT/uHM7oAjvq86RMAQ2lBYfjZinYwan2mnF5Ut9OxmkWUmKXqwCsTVLvQ0kCNYBmhUpw8L2utJiAV9AkEL74bCfh6gF1Y7fAuudk9b8nfjZCTwzgARTjb3SdCkfGHbI6EPKjBk0DMl/A++zy7H67VQaQYEh1PrE3+EubjJSy8LYmL76QoGngjXLDIPL2YvnSxafA9lAHvUiPEwTNaXIyhRecJqANOfL89myvmA64GOc7FyoTtUn2r7s07WvGbrB6NyRr7mTphBOBfvLk5atCLM3sJHibx77oeIzfQAw207xmsEytlxrYp7oiGE4wiZU64UXWw5GsUGGLVFu6cnJks+ZGWg221lxzdwt790bSJ9U7FBg8A7GuFuZFQxwmGq0y61qUE0IdYVyPXl+wgIigsVxR+uEhfSyAAmWuJuIJcpwIhbTmEe8A3cCNhxg7QiHkI1dejf9al8=",
                                      "salt" : "I3xgQrY95PZ94vrtviV6suELuuOnEQJQvFdCoM4WqTv7fXlXZO1Duw==",
                                      "nonce" : "hMysT5Qt7vcgyfNp",
                                      "authenticationTag" : "Ae7JkWFfaRR4vPFLcUkF7g=="
                                      })JSON";
    QJsonObject encryptedPrivateKeyData = QJsonDocument::fromJson(encryptedPrivateKeyJson.toLatin1()).object();
    QString metadataJson = R"JSON({
                           "version" : 1,
                           "recipients" : [ {
                           "userId" : null,
                           "certificate" : "MIIDQzCCAfegAwIBAgIBATBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAQUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAQUAogMCASAwDzENMAsGA1UEAwwEdGVzdDAeFw0xOTAxMjUxMzM4MTVaFw0xOTAyMjQxMzM4MTVaMA8xDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQClK5fsBsI79bed1waKhjbSkCIQCTnPu9rdG+AU8D9lRgYtxJF5GBkTDtaZHHZ81r56u5IvfCyRoxesBL2QwrlG8j2DfxGtxPSue/BaD2OzbOqbz1eoTiMuWS/36AwjoCXmOLab+wDyllXyw9wW1wZSm1UIiTaCIbpyWha/Yp5OoZk0AuIOLTdpP3wti/GTZhwx2z6ksa4g8NJRt7PUpaZmG59vYNpnhhEAXOUmokwAG+61E4GJ7yvU+gBcnZC37KfhM+qvhTLR/ubVVnuVs+5rIdTZeaEIiTxyuckGHHvh1HPLTfDjxdfcRIe/fh6xMy45jmLPkld+wKev604yPMBTAgMBAAGjQjBAMB8GA1UdIwQYMBaAFDVC3OBgUSKCQp+EeCV33Ac0MLhyMB0GA1UdDgQWBBQ1QtzgYFEigkKfhHgld9wHNDC4cjBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAQUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAQUAogMCASADggEBAKFduFONcHrPeJnFPbmemFJM86zEAOitHwVCxI9IkVEXKHiy0xHaC2NJoDePqpC/oHdwxQzMlHAA7z7h/BqvtYrX8IGDJ4oHvZ9v0k8Yrr4/k557i76Q83L7kJR/c5d7Hs+q++5MlcMmdtxu5Eidc84/Foqw0gij7P3U0dtnoKMhgnKY2O9EqXGeH0iCybQATk518pLXW+bTu8V3g/K8peQM6icQ+G7+eIPbmh5gobDFrLUxVu14QlmUn7kQPI5+/yKkxFSXlc8qf1JzMtkXayX9RlP0GzRKVyAZuJP/W6N2gqcTjOStXBGqHhqO4+fKnZop2HBSmED73dGFzDkTFcs=",
                           "encryptedKey" : "OoXGKt4iIO9a/MmwTIAED+G8rzb15j3BUe+s+iFVX+5dFqqJS3PFglNM4fB0K4I4eIAWsUnjytbc7Rcv5+W2RWEccbTchE/4G2xlxWSyQF9G9k2OfAw6lUOzpxv1W4CmNwUgYVBZkD9Q+7MJybn6mBfzf7KoZBh7CtGDsfTmpLoBJlIBCcXplMG92Qst1BXPCKCZ9LHrfKNPmMITvPPrpPko/Jj4Gmn3vQcrCKCUy9S+n/lD3Eskbx+hBej+eKKpEm6ViSdUSEV039tnB2/2cod2kSA+MJKcVvjsgrtGPXZ7h5CnWqTea/CdpeLk5Qh3Y/ISpp/FrH2kT08EMtL9Rw=="
                           } ],
                           "metadata" : {
                           "ciphertext" : "bA0o6m/e3CltZAuE5dUmWuFqid2iYZjo/UUrnKwgk/4f3OrZkaUhPA1bPJ5aqiR5L1uIodLxAz87MuNzHnznMkNdR9Zgzh8wxNVCsl1p6H346KBGhuV/QKJj8AuCxkTP8xQejpAWr31apqOtc6wuB7c0lAP2FQGzniqfwqZZRe+2Gwjo38FFhT2Ilbnb22VNMPMA/DBPEZZO0h+shP/FmPcyGpKiMryHfe91APViOppEGyP1QL28IIapROvDQBC3efD11FtkcpdeAkTljqaTglNKItENv8qw8BiBVpAiUmQ6eojhK5mALWOvIErP",
                           "nonce" : "clKBzaLhsN47mKgP",
                           "authenticationTag" : "TGYtDJ1vEu7a6q32WnQokg=="
                           }
                           })JSON";
    QJsonObject metadata = QJsonDocument::fromJson(metadataJson.toLatin1()).object();
    QByteArray certificate = QByteArray::fromBase64("MIIDQzCCAfegAwIBAgIBATBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAQUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAQUAogMCASAwDzENMAsGA1UEAwwEdGVzdDAeFw0xOTAxMjUxMzM4MTVaFw0xOTAyMjQxMzM4MTVaMA8xDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQClK5fsBsI79bed1waKhjbSkCIQCTnPu9rdG+AU8D9lRgYtxJF5GBkTDtaZHHZ81r56u5IvfCyRoxesBL2QwrlG8j2DfxGtxPSue/BaD2OzbOqbz1eoTiMuWS/36AwjoCXmOLab+wDyllXyw9wW1wZSm1UIiTaCIbpyWha/Yp5OoZk0AuIOLTdpP3wti/GTZhwx2z6ksa4g8NJRt7PUpaZmG59vYNpnhhEAXOUmokwAG+61E4GJ7yvU+gBcnZC37KfhM+qvhTLR/ubVVnuVs+5rIdTZeaEIiTxyuckGHHvh1HPLTfDjxdfcRIe/fh6xMy45jmLPkld+wKev604yPMBTAgMBAAGjQjBAMB8GA1UdIwQYMBaAFDVC3OBgUSKCQp+EeCV33Ac0MLhyMB0GA1UdDgQWBBQ1QtzgYFEigkKfhHgld9wHNDC4cjBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAQUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAQUAogMCASADggEBAKFduFONcHrPeJnFPbmemFJM86zEAOitHwVCxI9IkVEXKHiy0xHaC2NJoDePqpC/oHdwxQzMlHAA7z7h/BqvtYrX8IGDJ4oHvZ9v0k8Yrr4/k557i76Q83L7kJR/c5d7Hs+q++5MlcMmdtxu5Eidc84/Foqw0gij7P3U0dtnoKMhgnKY2O9EqXGeH0iCybQATk518pLXW+bTu8V3g/K8peQM6icQ+G7+eIPbmh5gobDFrLUxVu14QlmUn7kQPI5+/yKkxFSXlc8qf1JzMtkXayX9RlP0GzRKVyAZuJP/W6N2gqcTjOStXBGqHhqO4+fKnZop2HBSmED73dGFzDkTFcs=");

    auto privateKey = decryptPrivateKey(encryptedPrivateKeyData, mnemonic);
    auto recipient = findRecipient(certificate, metadata["recipients"].toArray());

    auto metadatakey = unwrapMetadataKey(privateKey, binaryJsonProperty(recipient, "encryptedKey"));

    //qDebug() << privateKey.toBase64() << endl;
    //qDebug() << recipient << endl;
    qDebug() << metadatakey << endl;
}
