package com.company;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import java.io.IOException;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class Main {

    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeyException, SignatureException {

        Security.addProvider(new BouncyCastleProvider());

        String EC_KEY = "BN8BY7JysR788RGv4m5lSsJwR9D+Homco9orJo2kD6yTr1KDYantSVbG4P87+8kO2OIJvpqoz0AwNImypuI7U\\/k=";
        String RSA_KEY = "MIIBCgKCAQEAxih38tVMUR1R712Cf\\/vGjgVNrsWdfNUifkAFcTTCclLEyEyDoVgX8oXZsyTJX7iy22cVmHrW3k20LynJAk77Hi9MP7qLU0iQmif\\/yLR+H5sqEhEaguFKr4eVR5VL6At3iIx8H4kceMWUBuhEJQp3d8vQIa6OY6wEP4FL+dao7xG6ZnZkyN78EoKw4D1FybgH2w44liVsrrMMEPXCddarL1OVHBcr8Kuv8TJNQ88Z6J2bEA9Z2sf1Pa+2mQa42XOaVPVO5r6YF0F+cCmGdVIRRnPdu90v56uHHYcaygqpV92nqX+ZJASoGpDfu2lYW8i0cvP6rHeCReUV2oi4jwfk8QIDAQAB";
        String EC_SIG = "MEUCIQCj1zUic7gP4asoF0sfu2eKMYMk0tU+qfdxRD3BrsDpYAIgVy4pZhOR9EMftD4WmRkSMzCk1FopUIsWMcTMzfhRcOc=";

        byte[] decodedECKey = Base64.getMimeDecoder().decode(EC_KEY);
        byte[] decodedRSAKey = Base64.getMimeDecoder().decode(RSA_KEY);

        for (int i = 0; i < decodedECKey.length; i++){
            System.out.print(decodedECKey[i]);
        }
        System.out.println("\n" + new String(Base64.getMimeDecoder().decode(EC_SIG)));
        //RSA KEY
        ASN1InputStream in = new ASN1InputStream(decodedRSAKey);
        ASN1Primitive obj = in.readObject();

        RSAPublicKey keyStruct = RSAPublicKey.getInstance(obj);
        RSAPublicKeySpec RSAKeySpec = new RSAPublicKeySpec(keyStruct.getModulus(), keyStruct.getPublicExponent());

        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey generatedPublic = kf.generatePublic(RSAKeySpec);

        //ECDSA KEY
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("prime256v1");
        KeyFactory ECkf = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        ECNamedCurveSpec params = new ECNamedCurveSpec("prime256v1", spec.getCurve(), spec.getG(), spec.getN());
        ECPoint point =  ECPointUtil.decodePoint(params.getCurve(), decodedECKey);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
        ECPublicKey pk = (ECPublicKey) ECkf.generatePublic(pubKeySpec);
        System.out.println(pk);

        Signature sig = Signature.getInstance("SHA256withECDSA");

        sig.initVerify(pk);

        sig.verify(Base64.getMimeDecoder().decode(EC_SIG));

//

//
//        System.out.println(generatedPublic);



//        PublicKey pubKey = KeyFactory.getInstance("RSA", "BC").generatePublic(new RSAPublicKeySpec())

    }
}
