package org.nextcloud.e2ee;

import static org.nextcloud.e2ee.NextcloudE2E.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;

import javax.crypto.SecretKey;

import org.nextcloud.e2ee.NextcloudE2E.DecryptedMetadata;
import org.nextcloud.e2ee.NextcloudE2E.FileMetadata;
import org.nextcloud.e2ee.NextcloudE2E.Metadata;
import org.nextcloud.e2ee.NextcloudE2E.PrivateKeyData;
import org.nextcloud.e2ee.NextcloudE2E.Recipient;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Decrypt a set of pregenerated sample data.
 * 
 * <ul>
 * <li>mnemonic: quarter plate lunch sick stone height canvas key scatter trust copper labor</li>
 * <li>plain filename: nc-917944991981588514.txt</li>
 * <li>plain file content: Hello World!</li>
 * </ul>
 * 
 * @author fichtelmannm
 *
 */
public class DecryptTestData
{
    public static void main( String[] args ) throws IOException, GeneralSecurityException
    {
        ObjectMapper json = new ObjectMapper();
        
        Metadata metadata = json.readValue( new File( "src/test/resources/metadata.json" ), Metadata.class );
        if ( metadata.version != 1 )
        {
            throw new IllegalStateException( "version not supported" );
        }
        
        String mnemonic = "quarter plate lunch sick stone height canvas key scatter trust copper labor";
        String fileid = "9d8a60ba240e4163a32b0438d7cbc884";
        PrivateKeyData privateKeyData = json.readValue( new File( "src/test/resources/keydata.json" ), PrivateKeyData.class );
        
        PrivateKey privateKey = decryptPrivateKey( privateKeyData, mnemonic );
        byte[] certificate = Files.readAllBytes( Paths.get( "src/test/resources/certificate.crt" ) );
        
        Recipient recipient = findRecipient( certificate, metadata.recipients );
        if ( recipient == null )
        {
            throw new IllegalStateException( "certificate not found in recipient list" );
        }
        
        SecretKey metadataKey = unwrapMetadataKey( privateKey, recipient.encryptedKey );
        
        DecryptedMetadata decryptedMetadata = decryptMetadata( metadataKey, metadata.metadata );
        
        FileMetadata fileMetadata = decryptedMetadata.files.get( fileid );
        
        File plainFile = new File( "/tmp/" + fileMetadata.name );
        decryptFile( fileMetadata, new File( "src/test/resources/" + fileid ), plainFile );
        
        System.out.println( "decrypted " + plainFile );
        Files.lines( plainFile.toPath() ).forEach( System.out::println );
    }
}
