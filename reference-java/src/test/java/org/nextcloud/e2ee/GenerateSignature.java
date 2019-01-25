package org.nextcloud.e2ee;

import static org.nextcloud.e2ee.NextcloudE2E.BC;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class GenerateSignature
{
    public static void main( String[] args ) throws OperatorCreationException, GeneralSecurityException, IOException, CMSException
    {
        byte[] tbs = "Hello World!".getBytes();
        
        KeyPairGenerator rsagen = KeyPairGenerator.getInstance( "RSA" );
        rsagen.initialize( 2048 );
        KeyPair keyPair = rsagen.generateKeyPair();
        X509Certificate x509 = Certificates.signCertificate( keyPair );
        
        CMSSignedDataGenerator signedDataGenerator = new CMSSignedDataGenerator();
        signedDataGenerator.addCertificates( new JcaCertStore( Collections.singleton( x509 ) ) );
        
        ContentSigner signer = new JcaContentSignerBuilder( "SHA256WithRSAAndMGF1" )
                .setProvider( BC )
                .build( keyPair.getPrivate() );
        signedDataGenerator.addSignerInfoGenerator( new SignerInfoGeneratorBuilder( new BcDigestCalculatorProvider() )
                .build( signer, new X509CertificateHolder( x509.getEncoded() ) ) );
        
        CMSSignedData signedData = signedDataGenerator.generate( new CMSProcessableByteArray( tbs ) );
        
        System.out.println( Base64.getMimeEncoder().encodeToString( signedData.getEncoded() ) );
    }
}
