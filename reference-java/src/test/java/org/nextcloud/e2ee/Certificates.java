package org.nextcloud.e2ee;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.ThreadLocalRandom;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class Certificates
{
    public static final Provider BC = new BouncyCastleProvider();
    
    public static X509Certificate signCertificate( PublicKey publicKey, PrivateKey signingKey, int idSize )
            throws OperatorCreationException, GeneralSecurityException, IOException
    {
        Date now = new Date();
        long duration = 1000L * 60 * 60 * 24 * 30;
        
        byte[] certId = new byte[idSize];
        ThreadLocalRandom.current().nextBytes( certId );
        
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo
                .getInstance( ASN1Sequence.getInstance( publicKey.getEncoded() ) );
        
        X500Name subject = new X500Name( "cn=test" );
        
        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder( subject, BigInteger.ONE, now,
                new Date( now.getTime() + duration ), subject, publicKeyInfo );
        
        X509CertificateHolder certificateHolder = certificateBuilder
                .addExtension( Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier( certId ) )
                .addExtension( Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier( certId ) )
                .build( new JcaContentSignerBuilder( "SHA256WithRSAandMGF1" ).setProvider( BC ).build( signingKey ) );
        
        CertificateFactory certificateFactory = CertificateFactory.getInstance( "X.509" );
        byte[] certBinary = certificateHolder.getEncoded();
        return (X509Certificate) certificateFactory.generateCertificate( new ByteArrayInputStream( certBinary ) );
    }
    
    public static X509Certificate signCertificate( KeyPair keys ) throws OperatorCreationException, GeneralSecurityException, IOException
    {
        return signCertificate( keys.getPublic(), keys.getPrivate(), 20 );
    }
}
