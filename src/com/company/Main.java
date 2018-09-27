package com.company;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class Main {

    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, IOException {

        Security.addProvider(new BouncyCastleProvider());

        String EC_KEY = "BJZG5j8Zr9vdujbgqVJbgoIXNnMqHSXUmrA+Ix0p133V6xm3XpX1SUGCA2UkM67afp1LhvbZZ6FTmT3MsqR7JkQ=";
        String RSA_KEY = "MIIBCgKCAQEAxih38tVMUR1R712Cf\\/vGjgVNrsWdfNUifkAFcTTCclLEyEyDoVgX8oXZsyTJX7iy22cVmHrW3k20LynJAk77Hi9MP7qLU0iQmif\\/yLR+H5sqEhEaguFKr4eVR5VL6At3iIx8H4kceMWUBuhEJQp3d8vQIa6OY6wEP4FL+dao7xG6ZnZkyN78EoKw4D1FybgH2w44liVsrrMMEPXCddarL1OVHBcr8Kuv8TJNQ88Z6J2bEA9Z2sf1Pa+2mQa42XOaVPVO5r6YF0F+cCmGdVIRRnPdu90v56uHHYcaygqpV92nqX+ZJASoGpDfu2lYW8i0cvP6rHeCReUV2oi4jwfk8QIDAQAB";

        byte[] decodedECKey = Base64.getDecoder().decode(EC_KEY);
        byte[] decodedRSAKey = Base64.getDecoder().decode(RSA_KEY);

        System.out.print(new String(decodedRSAKey));

        ASN1InputStream in = new ASN1InputStream(decodedRSAKey);
        ASN1Primitive obj = in.readObject();

        RSAPublicKey keyStruct = RSAPublicKey.getInstance(obj);
        RSAPublicKeySpec RSAKeySpec = new RSAPublicKeySpec(keyStruct.getModulus(), keyStruct.getPublicExponent());

        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey generatedPublic = kf.generatePublic(RSAKeySpec);


//        KeySpec keySpec = new ECPublicKeySpec(decodedECKey);
//
//        BigInteger modulus = pkcs1PublicKey.getModulus();
//        BigInteger publicExponent = pkcs1PublicKey.getPublicExponent();
//        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, publicExponent);
//

//
//        System.out.println(generatedPublic);



//        PublicKey pubKey = KeyFactory.getInstance("RSA", "BC").generatePublic(new RSAPublicKeySpec())

    }
}
