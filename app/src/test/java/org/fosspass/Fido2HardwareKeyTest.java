package org.fosspass;

import static org.junit.Assert.assertEquals;

import java.util.Base64;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

public class Fido2HardwareKeyTest {
    @Test
    public void verifiesRealEs256AssertionAndCounter() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair pair = generator.generateKeyPair();
        byte[] challenge = new byte[32];
        for (int i = 0; i < challenge.length; i++) challenge[i] = (byte) (i + 1);
        String challengeB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge);
        byte[] clientData = ("{\"type\":\"webauthn.get\",\"challenge\":\"" + challengeB64
                + "\",\"origin\":\"android:apk-key-hash:test\"}").getBytes(StandardCharsets.UTF_8);
        byte[] rpHash = MessageDigest.getInstance("SHA-256").digest("fosspass.local".getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream auth = new ByteArrayOutputStream();
        auth.write(rpHash);
        auth.write(0x05); // user present + user verified
        auth.write(ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(7).array());
        byte[] authData = auth.toByteArray();
        byte[] clientHash = MessageDigest.getInstance("SHA-256").digest(clientData);
        ByteArrayOutputStream signed = new ByteArrayOutputStream();
        signed.write(authData);
        signed.write(clientHash);
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(pair.getPrivate());
        signer.update(signed.toByteArray());
        byte[] signature = signer.sign();

        long counter = Fido2HardwareKey.verifyAssertion(
                pair.getPublic(), challenge, clientData, authData, signature, "fosspass.local", 0);
        assertEquals(7, counter);
    }

    @Test(expected = SecurityException.class)
    public void rejectsWrongChallenge() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair pair = generator.generateKeyPair();
        byte[] challenge = new byte[32];
        byte[] clientData = "{\"type\":\"webauthn.get\",\"challenge\":\"AAAA\"}"
                .getBytes(StandardCharsets.UTF_8);
        byte[] authData = new byte[37];
        authData[32] = 0x05;
        Fido2HardwareKey.verifyAssertion(pair.getPublic(), challenge, clientData, authData, new byte[0], "fosspass.local", 0);
    }
}
