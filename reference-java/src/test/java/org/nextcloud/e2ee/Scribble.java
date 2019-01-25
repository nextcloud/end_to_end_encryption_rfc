package org.nextcloud.e2ee;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.nextcloud.e2ee.NextcloudE2E.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.UUID;

import javax.crypto.SecretKey;

import org.bouncycastle.operator.OperatorCreationException;
import org.nextcloud.e2ee.NextcloudE2E.DecryptedMetadata;
import org.nextcloud.e2ee.NextcloudE2E.EncryptedMetadata;
import org.nextcloud.e2ee.NextcloudE2E.FileMetadata;
import org.nextcloud.e2ee.NextcloudE2E.Metadata;
import org.nextcloud.e2ee.NextcloudE2E.PrivateKeyData;
import org.nextcloud.e2ee.NextcloudE2E.Recipient;

public class Scribble
{
    public static void main( String[] args ) throws IOException, GeneralSecurityException, OperatorCreationException
    {
        // setup
        String mnemonic = "quarter plate lunch sick stone height canvas key scatter trust copper labor"
                .toLowerCase()
                .replaceAll( "\\s", "" );
        
        byte[] filePlaintext = "Hello World!\n".getBytes( US_ASCII );
        File plainFile = tmpFile( ".txt" );
        Files.write( plainFile.toPath(), filePlaintext );
        String fileid = UUID.randomUUID().toString().replace( "-", "" );
        
        // encryption
        SecretKey filekey = NextcloudE2E.generateKey();
        File encFile = tmpFile( ".enc" );
        FileMetadata fileMetadata = encryptFile( filekey, plainFile, encFile, "text/plain" );
        
        DecryptedMetadata decryptedMetadata = new DecryptedMetadata();
        decryptedMetadata.files.put( fileid, fileMetadata );
        
        SecretKey metadataKey = generateKey();
        
        EncryptedMetadata encryptedMetadata = encryptMetadata( metadataKey, decryptedMetadata );
        
        KeyPairGenerator rsagen = KeyPairGenerator.getInstance( "RSA" );
        rsagen.initialize( 2048 );
        KeyPair keyPair = rsagen.generateKeyPair();
        X509Certificate x509 = Certificates.signCertificate( keyPair );
        
        Recipient recipient = new Recipient();
        recipient.certificate = x509.getEncoded();
        recipient.encryptedKey = wrapMetadataKey( keyPair.getPublic(), metadataKey );
        
        Metadata metadata = new Metadata();
        metadata.recipients.add( recipient );
        metadata.metadata = encryptedMetadata;
        
        PrivateKeyData encryptedPrivateKey = encryptPrivateKey( keyPair.getPrivate(), mnemonic );
        
        // decryption
        PrivateKey privateKey = decryptPrivateKey( encryptedPrivateKey, mnemonic );
        
        recipient = findRecipient( x509.getEncoded(), metadata.recipients );
        Objects.requireNonNull( recipient, "no matching recipient found" );
        
        SecretKey metaKey = unwrapMetadataKey( privateKey, recipient.encryptedKey );
        DecryptedMetadata meta = decryptMetadata( metaKey, encryptedMetadata );
        FileMetadata fileMeta = meta.files.get( fileid );
        plainFile = new File( "/tmp/plain.txt" );
        decryptFile( fileMeta, encFile, plainFile );
        
        Files.lines( plainFile.toPath() ).forEach( System.out::println );
    }
    
    private static File tmpFile( String suffix ) throws IOException
    {
        File file = Files.createTempFile( "nc-", suffix ).toFile();
        file.deleteOnExit();
        return file;
    }
}
