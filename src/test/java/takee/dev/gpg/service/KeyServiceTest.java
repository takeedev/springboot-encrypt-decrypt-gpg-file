package takee.dev.gpg.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static takee.dev.gpg.service.GpgTestFixtures.loadPublicKey;
import static takee.dev.gpg.service.GpgTestFixtures.openPrivateKey;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class KeyServiceTest {

  private final KeyService keyService = new KeyService();

  @BeforeAll
  static void setUpProvider() {
    GpgTestFixtures.setUpProvider();
  }

  @Test
  @DisplayName("Should load encryption-capable public key")
  void shouldLoadEncryptionCapablePublicKey() throws Exception {
    PGPPublicKey publicKey = loadPublicKey(keyService);

    assertThat(publicKey.isEncryptionKey()).isTrue();
  }

  @Test
  @DisplayName("Should reject null public key stream")
  void shouldRejectNullPublicKeyStream() {
    assertThatThrownBy(() -> keyService.loadPublicKey(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("Public key input stream must not be null");
  }

  @Test
  @DisplayName("Should reject invalid public key stream")
  void shouldRejectInvalidPublicKeyStream() {
    InputStream invalidKey = new ByteArrayInputStream("invalid".getBytes(StandardCharsets.UTF_8));

    assertThatThrownBy(() -> keyService.loadPublicKey(invalidKey)).isInstanceOf(Exception.class);
  }

  @Test
  @DisplayName("Should load private key by key ID and clear passphrase")
  void shouldLoadPrivateKeyByKeyIdAndClearPassphrase() throws Exception {
    PGPPublicKey publicKey = loadPublicKey(keyService);
    char[] passphrase = "test".toCharArray();

    PGPPrivateKey privateKey =
        keyService.loadPrivateKey(openPrivateKey(), publicKey.getKeyID(), passphrase);

    assertThat(privateKey).isNotNull();
    assertThat(passphrase).containsOnly('\0');
  }

  @Test
  @DisplayName("Should reject null private key stream")
  void shouldRejectNullPrivateKeyStream() {
    assertThatThrownBy(() -> keyService.loadPrivateKey(null, 1L, "test".toCharArray()))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("Private key input stream must not be null");
  }

  @Test
  @DisplayName("Should reject null passphrase")
  void shouldRejectNullPassphrase() {
    assertThatThrownBy(() -> keyService.loadPrivateKey(openPrivateKey(), 1L, null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("Passphrase must not be null");
  }

  @Test
  @DisplayName("Should reject unknown private key ID")
  void shouldRejectUnknownPrivateKeyId() {
    assertThatThrownBy(() -> keyService.loadPrivateKey(openPrivateKey(), 0L, "test".toCharArray()))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("No private key found for key ID 0");
  }

  @Test
  @DisplayName("Should reject wrong passphrase and clear passphrase")
  void shouldRejectWrongPassphraseAndClearPassphrase() throws Exception {
    PGPPublicKey publicKey = loadPublicKey(keyService);
    char[] passphrase = "wrong".toCharArray();

    assertThatThrownBy(
            () -> keyService.loadPrivateKey(openPrivateKey(), publicKey.getKeyID(), passphrase))
        .isInstanceOf(Exception.class);
    assertThat(passphrase).containsOnly('\0');
  }
}
