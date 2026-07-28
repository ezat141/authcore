package com.authcore;

import com.authcore.keys.KeyCipher;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KeyCipherTest {

    private static final String KEY_A = Base64.getEncoder().encodeToString("0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8));
    private static final String KEY_B = Base64.getEncoder().encodeToString("fedcba9876543210fedcba9876543210".getBytes(StandardCharsets.UTF_8));

    private final KeyCipher cipher = new KeyCipher(KEY_A);

    @Test
    void encryptedMaterialRoundTrips() {
        byte[] secret = "private-key-bytes".getBytes(StandardCharsets.UTF_8);

        assertThat(cipher.decrypt(cipher.encrypt(secret))).isEqualTo(secret);
    }

    @Test
    void theSamePlaintextEncryptsDifferentlyEachTime() {
        byte[] secret = "private-key-bytes".getBytes(StandardCharsets.UTF_8);

        // A fresh nonce per encryption. Identical ciphertexts would leak that two keys
        // are the same, and reusing a nonce breaks GCM outright.
        assertThat(cipher.encrypt(secret)).isNotEqualTo(cipher.encrypt(secret));
    }

    @Test
    void adifferentMasterKeyCannotDecrypt() {
        String encrypted = cipher.encrypt("private-key-bytes".getBytes(StandardCharsets.UTF_8));

        assertThatThrownBy(() -> new KeyCipher(KEY_B).decrypt(encrypted))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void tamperedCiphertextIsRejectedRatherThanDecryptedToGarbage() {
        byte[] raw = Base64.getDecoder().decode(
                cipher.encrypt("private-key-bytes".getBytes(StandardCharsets.UTF_8)));
        raw[raw.length - 1] ^= 0x01;

        // This is why GCM rather than CBC: the tag makes the change detectable.
        assertThatThrownBy(() -> cipher.decrypt(Base64.getEncoder().encodeToString(raw)))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void aMasterKeyOfTheWrongLengthIsRejectedAtStartup() {
        String tooShort = Base64.getEncoder().encodeToString("short".getBytes(StandardCharsets.UTF_8));

        assertThatThrownBy(() -> new KeyCipher(tooShort))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("32 bytes");
    }
}
