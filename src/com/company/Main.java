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
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.*;
import java.security.interfaces.RSAKey;
import java.security.spec.*;
import java.util.Base64;

public class Main {

    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeyException, SignatureException {

        Security.addProvider(new BouncyCastleProvider());

        String EC_KEY = "BMk6X7WQJPjZlGo1F5PnwuY8lLolcCd61uUPrsiKmXORkcSNZp+mEJPvzTBwXamklYayxPCHyTfu14JlfgU8Acw=";
        String RSA_KEY = "MIGJAoGBAJ6HqaC7nCTztdt9fKGOiMCHwVI5ZFkHFbc0X3nECxCN+H52WCZ0z41J9p95Hg28V4V\\/yXEj9aICkHxY+\\/Kkju4041M7GxwN18S84w6qzSA34HePDyw7iq9RFuH2ut+IR+Mzy7krfR8\\/wMOV1wy3X30Uqro+HHx3S8lHqnj72HgDAgMBAAE=";
        String EC_SIG = "MEQCIHiVO6r7V8lTs4waI06ybXGuWNx60CSVpSvLSsX+70mNAiAoECukiWn4InfLdE4jjFKbMdM65opMqXST4cB1xQJaJA==";
        String RSA_SIG = "YWI0Tj8Cw3Q8TQPaidHLlx7XB+4DoAWDA8jvcviijWuUiYXKOIWV+md4rQ3wIFAwyILvbhVUYO4wmXqfQeeoKQ==";

        String ChallengeB64 = "MzljZmJiMWItYmFmNC00MGRkLTgxMzQtNGE5ZGQzZGE5OGRl";

        String PayloadB64 = "eyJLZXlUeXBlIjoiUlNBIiwiUHVibGljS2V5QjY0IjoiTUlHSkFvR0JBSjZIcWFDN25DVHp0ZHQ5ZktHT2lNQ0h3Vkk1WkZrSEZiYzBYM25FQ3hDTitINTJXQ1owejQxSjlwOTVIZzI4VjRWXC95WEVqOWFJQ2tIeFkrXC9La2p1NDA0MU03R3h3TjE4Uzg0dzZxelNBMzRIZVBEeXc3aXE5UkZ1SDJ1dCtJUitNenk3a3JmUjhcL3dNT1Yxd3kzWDMwVXFybytISHgzUzhsSHFuajcySGdEQWdNQkFBRT0ifQ==";

        byte[] decodedECKey = Base64.getMimeDecoder().decode(EC_KEY);
        byte[] decodedRSAKey = Base64.getMimeDecoder().decode(RSA_KEY);

        System.out.println(new String(decodedRSAKey));

        for (int i = 0; i < decodedECKey.length; i++){
            System.out.print(decodedRSAKey[i]);
        }
        System.out.println("\n" + new String(Base64.getDecoder().decode(EC_SIG)));
        //RSA KEY
        ASN1InputStream in = new ASN1InputStream(decodedRSAKey);
        ASN1Primitive obj = in.readObject();

        RSAPublicKey keyStruct = RSAPublicKey.getInstance(obj);
        RSAPublicKeySpec RSAKeySpec = new RSAPublicKeySpec(keyStruct.getModulus(), keyStruct.getPublicExponent());

        KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
        PublicKey generatedPublic = kf.generatePublic(RSAKeySpec);
        java.security.interfaces.RSAPublicKey rsa = (java.security.interfaces.RSAPublicKey)generatedPublic;
        System.out.println(rsa.getModulus().toByteArray().length);

        //ECDSA KEY
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
        KeyFactory ECkf = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        ECNamedCurveSpec params = new ECNamedCurveSpec("secp256r1", spec.getCurve(), spec.getG(), spec.getN());
        ECPoint point =  ECPointUtil.decodePoint(params.getCurve(), decodedECKey);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
        ECPublicKey pk = (ECPublicKey) ECkf.generatePublic(pubKeySpec);
        System.out.println(pk);

        Signature sig = Signature.getInstance("SHA256withECDSA");

        sig.initVerify(pk);

        sig.update("Hello World".getBytes());

        byte[] decodedSig = Base64.getDecoder().decode(EC_SIG);

        ByteBuffer buffer = ByteBuffer.wrap(decodedSig);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        byte[] BEDecodedSig = buffer.array();

        boolean result = sig.verify(decodedSig);

        if (result) {
            System.out.println("Success!");
        }

//        EC Public Key [1d:d7:9f:7c:a5:e1:b6:d0:ed:9d:fa:8e:5b:4c:fa:0f:0f:d5:e7:2f]
//        X: df0163b272b11efcf111afe26e654ac27047d0fe1e899ca3da2b268da40fac93
//        Y: af528361a9ed4956c6e0ff3bfbc90ed8e209be9aa8cf40303489b2a6e23b53f9

//

//
//        System.out.println(generatedPublic);



//        PublicKey pubKey = KeyFactory.getInstance("RSA", "BC").generatePublic(new RSAPublicKeySpec())

    }
}
