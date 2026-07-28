package com.authcore.keys;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Encrypts signing-key private material before it is written to the database.
 *
 * <p>Without this, anyone who can read a row — a backup, a replica, a leaked dump, an
 * over-broad {@code SELECT} — can mint tokens indistinguishable from the real thing. A
 * stolen signing key is worse than a stolen password: it forges every identity at once
 * and leaves no trace in the audit log.
 *
 * <p>AES-GCM, so tampering is detected rather than silently decrypting to garbage. The
 * nonce is random per encryption and stored alongside the ciphertext; reusing a nonce
 * under the same key would destroy GCM's guarantees entirely.
 *
 * <p>The master key comes from configuration, which moves the secret out of the database
 * but not out of the deployment. A production system should hold it in a KMS or HSM so
 * the private key is never assembled in application memory at all — see the README.
 */
public class KeyCipher {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int NONCE_LENGTH = 12;
    private static final int TAG_LENGTH_BITS = 128;

    private final SecretKeySpec masterKey;
    private final SecureRandom random = new SecureRandom();

    public KeyCipher(String base64MasterKey) {
        byte[] keyBytes = Base64.getDecoder().decode(base64MasterKey);
        if (keyBytes.length != 32) {
            throw new IllegalArgumentException(
                    "Master key must be 32 bytes (AES-256); got " + keyBytes.length);
        }
        this.masterKey = new SecretKeySpec(keyBytes, "AES");
    }

    public String encrypt(byte[] plaintext) {
        try {
            byte[] nonce = new byte[NONCE_LENGTH];
            random.nextBytes(nonce);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, masterKey, new GCMParameterSpec(TAG_LENGTH_BITS, nonce));
            byte[] ciphertext = cipher.doFinal(plaintext);

            // nonce || ciphertext, so decryption needs nothing but this one string.
            return Base64.getEncoder().encodeToString(
                    ByteBuffer.allocate(nonce.length + ciphertext.length)
                            .put(nonce)
                            .put(ciphertext)
                            .array());
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to encrypt signing key", ex);
        }
    }

    public byte[] decrypt(String encoded) {
        try {
            ByteBuffer buffer = ByteBuffer.wrap(Base64.getDecoder().decode(encoded));

            byte[] nonce = new byte[NONCE_LENGTH];
            buffer.get(nonce);
            byte[] ciphertext = new byte[buffer.remaining()];
            buffer.get(ciphertext);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, masterKey, new GCMParameterSpec(TAG_LENGTH_BITS, nonce));
            return cipher.doFinal(ciphertext);
        } catch (Exception ex) {
            // Usually a changed master key or a tampered row. Both mean the key is
            // unusable, and signing with a half-trusted key is not an option.
            throw new IllegalStateException("Failed to decrypt signing key", ex);
        }
    }
}
