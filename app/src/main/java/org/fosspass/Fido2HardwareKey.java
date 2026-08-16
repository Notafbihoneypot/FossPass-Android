package org.fosspass;

import com.google.android.gms.fido.common.Transport;
import com.google.android.gms.fido.fido2.api.common.Attachment;
import com.google.android.gms.fido.fido2.api.common.AttestationConveyancePreference;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorSelectionCriteria;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialCreationOptions;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialDescriptor;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialParameters;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialRequestOptions;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialRpEntity;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialUserEntity;
import com.upokecenter.cbor.CBORObject;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Offline WebAuthn/FIDO2 request construction and assertion verification. */
public final class Fido2HardwareKey {
    public static final String RP_ID = "fosspass.local";
    private static final SecureRandom RANDOM = new SecureRandom();

    private Fido2HardwareKey() {}

    public static byte[] challenge() {
        byte[] value = new byte[32];
        RANDOM.nextBytes(value);
        return value;
    }

    public static PublicKeyCredentialCreationOptions registrationOptions(byte[] challenge, byte[] userId) {
        PublicKeyCredentialRpEntity rp = new PublicKeyCredentialRpEntity(RP_ID, "FossPass", null);
        PublicKeyCredentialUserEntity user = new PublicKeyCredentialUserEntity(userId, "local-vault", null, "FossPass local vault");
        List<PublicKeyCredentialParameters> algorithms = Collections.singletonList(
                new PublicKeyCredentialParameters("public-key", -7)); // ES256
        AuthenticatorSelectionCriteria selection = new AuthenticatorSelectionCriteria.Builder()
                .setAttachment(Attachment.CROSS_PLATFORM)
                .setRequireResidentKey(false)
                .build();
        return new PublicKeyCredentialCreationOptions.Builder()
                .setRp(rp)
                .setUser(user)
                .setChallenge(challenge)
                .setParameters(algorithms)
                .setAuthenticatorSelection(selection)
                .setAttestationConveyancePreference(AttestationConveyancePreference.NONE)
                .setTimeoutSeconds(60.0)
                .build();
    }

    public static PublicKeyCredentialRequestOptions assertionOptions(byte[] challenge, byte[] credentialId) {
        PublicKeyCredentialDescriptor descriptor = new PublicKeyCredentialDescriptor(
                "public-key", credentialId, (List<Transport>) null);
        return new PublicKeyCredentialRequestOptions.Builder()
                .setChallenge(challenge)
                .setRpId(RP_ID)
                .setAllowList(Collections.singletonList(descriptor))
                .setTimeoutSeconds(60.0)
                .build();
    }

    public static PublicKey extractEs256PublicKey(byte[] attestationObject) throws Exception {
        CBORObject attestation = CBORObject.DecodeFromBytes(attestationObject);
        byte[] authData = attestation.get(CBORObject.FromObject("authData")).GetByteString();
        if (authData.length < 55 || (authData[32] & 0x40) == 0) {
            throw new SecurityException("FIDO registration omitted attested credential data");
        }
        int credentialLength = ((authData[53] & 0xff) << 8) | (authData[54] & 0xff);
        int coseOffset = 55 + credentialLength;
        if (credentialLength == 0 || coseOffset >= authData.length) {
            throw new SecurityException("Invalid FIDO credential data");
        }
        CBORObject cose = CBORObject.Read(new ByteArrayInputStream(authData, coseOffset, authData.length - coseOffset));
        int keyType = cose.get(CBORObject.FromObject(1)).AsInt32();
        int algorithm = cose.get(CBORObject.FromObject(3)).AsInt32();
        int curve = cose.get(CBORObject.FromObject(-1)).AsInt32();
        if (keyType != 2 || algorithm != -7 || curve != 1) {
            throw new SecurityException("Only ES256 P-256 hardware credentials are supported");
        }
        byte[] x = cose.get(CBORObject.FromObject(-2)).GetByteString();
        byte[] y = cose.get(CBORObject.FromObject(-3)).GetByteString();
        if (x.length != 32 || y.length != 32) throw new SecurityException("Invalid P-256 key");
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec spec = parameters.getParameterSpec(ECParameterSpec.class);
        ECPoint point = new ECPoint(new java.math.BigInteger(1, x), new java.math.BigInteger(1, y));
        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, spec));
    }

    public static void verifyRegistration(byte[] expectedChallenge, byte[] clientDataJson, byte[] attestationObject) throws Exception {
        verifyClientData(expectedChallenge, clientDataJson, "webauthn.create");
        CBORObject attestation = CBORObject.DecodeFromBytes(attestationObject);
        byte[] authData = attestation.get(CBORObject.FromObject("authData")).GetByteString();
        verifyRpAndFlags(authData);
        extractEs256PublicKey(attestationObject);
    }

    public static long verifyAssertion(PublicKey publicKey, byte[] expectedChallenge,
                                       byte[] clientDataJson, byte[] authenticatorData,
                                       byte[] signatureBytes, String rpId,
                                       long previousCounter) throws Exception {
        verifyClientData(expectedChallenge, clientDataJson, "webauthn.get");
        if (!RP_ID.equals(rpId)) throw new SecurityException("Unexpected relying party");
        verifyRpAndFlags(authenticatorData);
        long counter = Integer.toUnsignedLong(ByteBuffer.wrap(authenticatorData, 33, 4)
                .order(ByteOrder.BIG_ENDIAN).getInt());
        if (previousCounter != 0 && counter != 0 && counter <= previousCounter) {
            throw new SecurityException("Authenticator counter replay detected");
        }
        byte[] clientHash = MessageDigest.getInstance("SHA-256").digest(clientDataJson);
        ByteArrayOutputStream signedData = new ByteArrayOutputStream();
        signedData.write(authenticatorData);
        signedData.write(clientHash);
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(publicKey);
        verifier.update(signedData.toByteArray());
        if (!verifier.verify(signatureBytes)) throw new SecurityException("Invalid hardware-key signature");
        return counter;
    }

    private static void verifyClientData(byte[] expectedChallenge, byte[] clientDataJson, String expectedType) throws Exception {
        String json = new String(clientDataJson, StandardCharsets.UTF_8);
        String type = jsonStringField(json, "type");
        String challenge = jsonStringField(json, "challenge");
        if (!expectedType.equals(type)) throw new SecurityException("Invalid WebAuthn operation");
        byte[] actualChallenge = Base64.getUrlDecoder().decode(challenge);
        if (!MessageDigest.isEqual(expectedChallenge, actualChallenge)) throw new SecurityException("FIDO challenge mismatch");
    }

    private static String jsonStringField(String json, String field) {
        Pattern pattern = Pattern.compile("\\\"" + Pattern.quote(field) + "\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");
        Matcher matcher = pattern.matcher(json);
        if (!matcher.find()) throw new SecurityException("Missing WebAuthn " + field);
        return matcher.group(1);
    }

    private static void verifyRpAndFlags(byte[] authData) throws Exception {
        if (authData.length < 37) throw new SecurityException("Authenticator data is truncated");
        byte[] expectedRpHash = MessageDigest.getInstance("SHA-256").digest(RP_ID.getBytes(StandardCharsets.UTF_8));
        if (!MessageDigest.isEqual(expectedRpHash, Arrays.copyOfRange(authData, 0, 32))) {
            throw new SecurityException("FIDO relying-party mismatch");
        }
        int flags = authData[32] & 0xff;
        if ((flags & 0x01) == 0) throw new SecurityException("Hardware key did not confirm user presence");
        if ((flags & 0x04) == 0) throw new SecurityException("Hardware key did not verify the user");
    }
}
