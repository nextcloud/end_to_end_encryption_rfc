package org.nextcloud.e2ee;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.io.SequenceInputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.Streams;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * List of functions related to nextcloud e2ee feature (end to end encryption).
 * 
 * <p/>
 * This is how it works: On registration, a user generates a pair of RSA-2048 keys and lets the backend sign a X.509 Certificate containing
 * the public key.
 * <p/>
 * A user also has a secret passphrase called mnemonic that is stored in a local keychain or something alike. For storing the private key on
 * the server for device distribution it is encrypted based on the mnemonic.
 * </p>
 * encrypt/decrypt the private key: {@link #encryptPrivateKey(PrivateKey, String)}, {@link #decryptPrivateKey(PrivateKeyData, String)}
 * 
 * @see <a href="https://github.com/nextcloud/end_to_end_encryption_rfc">nextcloud/end_to_end_encryption_rfc</a>
 * @author Max Fichtelmann <max.fichtelmann@gmail.com>
 *
 */
public class NextcloudE2E
{
    public static final Provider     BC               = new BouncyCastleProvider();
    public static final SecureRandom RNG              = new SecureRandom();
    
    public static final int          GCM_TAG_LENGTH   = 128;
    public static final int          GCM_NONCE_LENGTH = 96;
    public static final String       AES_GCM          = "AES/GCM/NoPadding";
    public static final String       RSA_OAEP         = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    public static final String       PBKDF            = "PBKDF2WithHmacSHA1";
    
    /**
     * Select the recipient matching the provided certificate.
     * 
     * @param certificate
     *            the certificate to search for
     * @param recipients
     *            the list of recipients
     * @return the recipient for which the certificate matches the input certificate or <code>null</code> if none matches.
     */
    public static Recipient findRecipient( byte[] certificate, List<Recipient> recipients )
    {
        for ( Recipient recipient : recipients )
        {
            if ( Arrays.equals( recipient.certificate, certificate ) )
            {
                return recipient;
            }
        }
        
        return null;
    }
    
    /**
     * Decrypt a private key, based on the operations described in {@link #encryptPrivateKey(PrivateKey, String)}.
     * 
     * @param data
     *            the public information needed to decrypt the key
     * @param mnemonic
     *            the secret passphrase
     * @return the private key, ready to perform decryption/signature operations
     * @throws GeneralSecurityException
     *             if a cryptographic operation fails.
     */
    public static PrivateKey decryptPrivateKey( PrivateKeyData data, String mnemonic ) throws GeneralSecurityException
    {
        SecretKey keyEncryptionKey = deriveKeyEncryptionKey( mnemonic, data.salt );
        
        Cipher cipher = Cipher.getInstance( AES_GCM, BC );
        cipher.init( Cipher.UNWRAP_MODE, keyEncryptionKey, new GCMParameterSpec( GCM_TAG_LENGTH, data.nonce ) );
        
        ByteBuffer encryptedKey = ByteBuffer.allocate( data.encryptedKey.length + data.authenticationTag.length );
        encryptedKey.put( data.encryptedKey );
        encryptedKey.put( data.authenticationTag );
        
        return (PrivateKey) cipher.unwrap( encryptedKey.array(), "RSA", Cipher.PRIVATE_KEY );
    }
    
    /**
     * Encrypt the RSA private key based on a key derived from the mnemonic.
     * <p/>
     * <ol>
     * <li>derive an AES-256 key by applying PBKDF2-HMAC-SHA1 to
     * <ul>
     * <li>a random 40-byte salt</li>
     * <li>the normalized mnemonic (all lowercase, all whitespace removed)</li>
     * <li>1024 iterations</li>
     * </ul>
     * </li>
     * <li>encrypt the private key using AES-GCM with the derived key</li>
     * <li>construct a datastructure later presented as json
     * <ul>
     * <li>salt: the generated 40-bytes salt used during key derivation</li>
     * <li>nonce: the generated 96-bit nonce used during GCM encryption</li>
     * <li>authenticationTag: the authentication tag emitted by GCM</li>
     * <li>encryptedKey: the ciphertext - not including the authenticationTag</li>
     * </ul>
     * </li>
     * </ol>
     * 
     * @param key
     *            the plain RSA-2048 private key
     * @param mnemonic
     *            the mnemonic passphrase
     * @return a json-representable structure containing public information needed to later decrypt the key when combined with the mnemonic.
     * @throws GeneralSecurityException
     *             if a cryptographic operation fails
     */
    public static PrivateKeyData encryptPrivateKey( PrivateKey key, String mnemonic ) throws GeneralSecurityException
    {
        byte[] salt = new byte[40];
        RNG.nextBytes( salt );
        SecretKey keyEncryptionKey = deriveKeyEncryptionKey( mnemonic, salt );
        
        byte[] nonce = generateGcmNonce();
        
        Cipher cipher = Cipher.getInstance( AES_GCM, BC );
        cipher.init( Cipher.WRAP_MODE, keyEncryptionKey, new GCMParameterSpec( GCM_TAG_LENGTH, nonce ) );
        
        byte[] encryptedKeyWithTag = cipher.wrap( key );
        
        byte[] encryptedKey = Arrays.copyOfRange( encryptedKeyWithTag, 0, encryptedKeyWithTag.length - GCM_TAG_LENGTH / 8 );
        byte[] authTag = Arrays.copyOfRange( encryptedKeyWithTag, encryptedKey.length, encryptedKeyWithTag.length );
        
        PrivateKeyData keyData = new PrivateKeyData();
        keyData.salt = salt;
        keyData.nonce = cipher.getIV();
        keyData.authenticationTag = authTag;
        keyData.encryptedKey = encryptedKey;
        return keyData;
    }
    
    private static SecretKey deriveKeyEncryptionKey( String mnemonic, byte[] salt ) throws GeneralSecurityException
    {
        PBEKeySpec keySpec = new PBEKeySpec(
                mnemonic
                        .toLowerCase()
                        .replaceAll( "\\s", "" )
                        .toCharArray(),
                salt,
                1024,
                256 );
        
        SecretKeyFactory pbkdf = SecretKeyFactory.getInstance( "PBKDF2WithHmacSHA1" );
        SecretKey kek = pbkdf.generateSecret( keySpec );
        
        return new SecretKeySpec( kek.getEncoded(), "AES" );
    }
    
    /**
     * Decrypt the encrypted metadata key.
     * 
     * Use RSA OAEP with SHA-256 (MGF1 with SHA-256) to decrypt the key.
     * 
     * @param key
     *            the private key to decrypt the symmetric key.
     * @param ciphertext
     *            the encrypted symmetric metadata key.
     * @return the unwrapped metadata key, ready to use.
     * @throws GeneralSecurityException
     *             if decryption fails
     */
    public static SecretKey unwrapMetadataKey( PrivateKey key, byte[] ciphertext ) throws GeneralSecurityException
    {
        Cipher rsa = Cipher.getInstance( RSA_OAEP );
        rsa.init( Cipher.UNWRAP_MODE, key );
        
        return (SecretKey) rsa.unwrap( ciphertext, "AES", Cipher.SECRET_KEY );
    }
    
    /**
     * Encrypt the metadata key.
     * 
     * Use RSA OAEP with SHA-256 (MGF1 with SHA-256) to encrypt the key.
     * 
     * @param key
     *            the private key to use for encryption.
     * @param metadataKey
     *            the key to be encrypted/wrapped.
     * @return the encrypted key binary.
     * @throws GeneralSecurityException
     *             if encryption fails
     */
    public static byte[] wrapMetadataKey( PublicKey key, SecretKey metadataKey ) throws GeneralSecurityException
    {
        Cipher rsa = Cipher.getInstance( RSA_OAEP );
        rsa.init( Cipher.WRAP_MODE, key );
        
        return rsa.wrap( metadataKey );
    }
    
    /**
     * Decrypt the metadata by performing the reverse steps laid out in {@link #encryptMetadata(SecretKey, DecryptedMetadata)}.
     * 
     * @param metadataKey
     *            the key to decrypt the metadata
     * @param encryptedMetadata
     *            the encrypted metadata
     * @return the decrypted and uncompressed parsed meta information
     * @throws GeneralSecurityException
     *             if decryption fails
     * @throws IOException
     *             if gzip or json parsing fails
     */
    public static DecryptedMetadata decryptMetadata( SecretKey metadataKey, EncryptedMetadata encryptedMetadata )
            throws GeneralSecurityException, IOException
    {
        Cipher cipher = Cipher.getInstance( AES_GCM, BC );
        cipher.init( Cipher.DECRYPT_MODE, metadataKey, new GCMParameterSpec( GCM_TAG_LENGTH, encryptedMetadata.nonce ) );
        
        ByteArrayOutputStream plain = new ByteArrayOutputStream( encryptedMetadata.ciphertext.length );
        plain.write( cipher.update( encryptedMetadata.ciphertext ) );
        plain.write( cipher.doFinal( encryptedMetadata.authenticationTag ) );
        
        try ( InputStream json = new GZIPInputStream( new ByteArrayInputStream( plain.toByteArray() ) ) )
        {
            return new ObjectMapper().readValue( json, DecryptedMetadata.class );
        }
    }
    
    /**
     * Encrypt the metadata using the metadata key.
     * 
     * <ol>
     * <li>Serialize the input metadata structure to json</li>
     * <li>gzip the json</li>
     * <li>encrypt the gzipped data using AES-GCM</li>
     * </ol>
     * 
     * @param metadataKey
     *            the key to encrypt the metadata with
     * @param plainMetadata
     *            the unencrypted metadata structure.
     * @return a structure containing the encrypted structure, the nonce and authentication tag.
     * @throws GeneralSecurityException
     *             if encryption fails
     * @throws IOException
     *             if json serialization or gzip fail
     */
    public static EncryptedMetadata encryptMetadata( SecretKey metadataKey, DecryptedMetadata plainMetadata )
            throws GeneralSecurityException, IOException
    {
        ByteArrayOutputStream compressedMetadata = new ByteArrayOutputStream();
        try ( OutputStream zipped = new GZIPOutputStream( compressedMetadata ) )
        {
            new ObjectMapper().writeValue( zipped, plainMetadata );
        }
        
        byte[] nonce = generateGcmNonce();
        byte[] authTag = new byte[GCM_TAG_LENGTH / 8];
        
        Cipher cipher = Cipher.getInstance( AES_GCM, BC );
        cipher.init( Cipher.ENCRYPT_MODE, metadataKey, new GCMParameterSpec( GCM_TAG_LENGTH, nonce ) );
        
        byte[] ciphertextWithTag = cipher.doFinal( compressedMetadata.toByteArray() );
        byte[] ciphertext = new byte[ciphertextWithTag.length - authTag.length];
        
        System.arraycopy( ciphertextWithTag, ciphertext.length, authTag, 0, authTag.length );
        System.arraycopy( ciphertextWithTag, 0, ciphertext, 0, ciphertext.length );
        
        EncryptedMetadata result = new EncryptedMetadata();
        result.authenticationTag = authTag;
        result.nonce = nonce;
        result.ciphertext = ciphertext;
        
        return result;
    }
    
    /**
     * Decrypt a file using key, nonce and authenticationTag provided with the {@link FileMetadata}.
     * 
     * @param info
     *            the metadata containing key material, nonce and authenticationTag.
     * @param encryptedFile
     *            the file containing the encrypted data (access: read)
     * @param target
     *            the file the plaintext is stored in (access: write, create)
     * @throws GeneralSecurityException
     *             if decryption fails
     * @throws IOException
     *             if reading or writing a file fails
     */
    public static void decryptFile( FileMetadata info, File encryptedFile, File target ) throws GeneralSecurityException, IOException
    {
        Cipher cipher = Cipher.getInstance( AES_GCM, BC );
        cipher.init( Cipher.DECRYPT_MODE, new SecretKeySpec( info.key, "AES" ), new GCMParameterSpec( GCM_TAG_LENGTH, info.nonce ) );
        
        try ( InputStream fileStream = new FileInputStream( encryptedFile );
                InputStream source = new CipherInputStream(
                        new SequenceInputStream( fileStream, new ByteArrayInputStream( info.authenticationTag ) ),
                        cipher );
                OutputStream plain = new FileOutputStream( target ) )
        {
            Streams.pipeAll( source, plain );
        }
    }
    
    /**
     * Encrypt a file, store the resulting ciphertext in the target file and return the metadata associated with the file.
     * 
     * @param plainFile
     *            the file reference to the plaintext file (access: read)
     * @param target
     *            the file the ciphertext is stored in (access: read, write, create)
     * @param mimetype
     *            the mimetype of the file
     * @return the file metadata with the original filename, nonce, key and authentication tag.
     * @throws GeneralSecurityException
     *             if encryption fails
     * @throws IOException
     *             if reading from the input or writing to the output fails.
     */
    public static FileMetadata encryptFile( File plainFile, File target, String mimetype )
            throws GeneralSecurityException, IOException
    {
        SecretKey fileKey = generateAesKey();
        byte[] nonce = generateGcmNonce();
        byte[] authTag = new byte[GCM_TAG_LENGTH / 8];
        
        Cipher cipher = Cipher.getInstance( AES_GCM, BC );
        cipher.init( Cipher.ENCRYPT_MODE, fileKey, new GCMParameterSpec( GCM_TAG_LENGTH, nonce ) );
        
        try ( InputStream plain = new FileInputStream( plainFile );
                OutputStream encrypted = new CipherOutputStream( new FileOutputStream( target ), cipher ) )
        {
            Streams.pipeAll( plain, encrypted );
        }
        
        // important: after closing above cipher stream - dont merge the try-blocks
        try ( RandomAccessFile edit = new RandomAccessFile( target, "rw" ) )
        {
            edit.seek( edit.length() - authTag.length );
            edit.read( authTag );
            edit.setLength( edit.length() - authTag.length );
        }
        
        FileMetadata metadata = new FileMetadata();
        metadata.mimetype = mimetype;
        metadata.name = plainFile.getName();
        metadata.nonce = nonce;
        metadata.authenticationTag = authTag;
        metadata.key = fileKey.getEncoded();
        return metadata;
    }
    
    private static byte[] generateGcmNonce()
    {
        byte[] nonce = new byte[GCM_NONCE_LENGTH / 8];
        RNG.nextBytes( nonce );
        
        return nonce;
    }
    
    public static SecretKey generateAesKey() throws NoSuchAlgorithmException
    {
        return KeyGenerator.getInstance( "AES" ).generateKey();
    }
    
    public static class PrivateKeyData
    {
        public byte[] encryptedKey;
        public byte[] salt;
        public byte[] nonce;
        public byte[] authenticationTag;
    }
    
    public static class DecryptedMetadata
    {
        public List<byte[]>                keyChecksums = new ArrayList<>();
        public int                         counter      = 0;
        public Map<String, FolderMetadata> folders      = new HashMap<>();
        public Map<String, FileMetadata>   files        = new HashMap<>();
    }
    
    public static class FolderMetadata
    {
        public String name;
    }
    
    public static class FileMetadata
    {
        public String name;
        public String mimetype;
        public byte[] nonce;
        public byte[] authenticationTag;
        public byte[] key;
    }
    
    public static class Metadata
    {
        public int               version    = 1;
        public List<Recipient>   recipients = new ArrayList<>();
        public EncryptedMetadata metadata;
    }
    
    public static class Recipient
    {
        public String userId;
        public byte[] certificate;
        public byte[] encryptedKey;
    }
    
    public static class EncryptedMetadata
    {
        public byte[] ciphertext;
        public byte[] nonce;
        public byte[] authenticationTag;
    }
}
