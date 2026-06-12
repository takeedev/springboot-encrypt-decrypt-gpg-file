package takee.dev.gpg;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.same;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import takee.dev.gpg.config.BouncyCastleConfig;
import takee.dev.gpg.service.DecryptionService;
import takee.dev.gpg.service.EncryptionService;
import takee.dev.gpg.service.KeyService;

@ExtendWith(MockitoExtension.class)
class GpgApplicationTests {

  private static final Path PUBLIC_KEY_PATH = Path.of("src/main/resources/keys/public_key.asc");
  private static final Path PRIVATE_KEY_PATH = Path.of("src/main/resources/keys/private_key.asc");
  private static final Path PLAIN_TEXT_PATH = Path.of("src/test/java/resource/example.txt");

  private final KeyService keyService = new KeyService();
  private final EncryptionService encryptionService = new EncryptionService();

  @Mock private KeyService mockedKeyService;

  @BeforeAll
  static void setUpProvider() {
    new BouncyCastleConfig();
  }

  @Nested
  class KeyServiceTests {

    @Test
    @DisplayName("Should load encryption-capable public key")
    void shouldLoadEncryptionCapablePublicKey() throws Exception {
      PGPPublicKey publicKey = loadPublicKey();

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
      PGPPublicKey publicKey = loadPublicKey();
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
      assertThatThrownBy(
              () -> keyService.loadPrivateKey(openPrivateKey(), 0L, "test".toCharArray()))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessage("No private key found for key ID 0");
    }

    @Test
    @DisplayName("Should reject wrong passphrase and clear passphrase")
    void shouldRejectWrongPassphraseAndClearPassphrase() throws Exception {
      PGPPublicKey publicKey = loadPublicKey();
      char[] passphrase = "wrong".toCharArray();

      assertThatThrownBy(
              () -> keyService.loadPrivateKey(openPrivateKey(), publicKey.getKeyID(), passphrase))
          .isInstanceOf(Exception.class);
      assertThat(passphrase).containsOnly('\0');
    }
  }

  @Nested
  class EncryptionServiceTests {

    @Test
    @DisplayName("Should encrypt plaintext into PGP payload")
    void shouldEncryptPlaintextIntoPgpPayload() throws Exception {
      byte[] encrypted = encryptExampleText();

      assertThat(encrypted).isNotEmpty();
      assertThat(new String(encrypted, StandardCharsets.UTF_8)).doesNotContain(readExampleText());
    }
  }

  @Nested
  class DecryptionServiceTests {

    @Test
    @DisplayName("Should decrypt encrypted payload with private key selected by packet key ID")
    void shouldDecryptEncryptedPayloadWithPrivateKeySelectedByPacketKeyId() throws Exception {
      byte[] encrypted = encryptExampleText();
      PGPPublicKey publicKey = loadPublicKey();
      PGPPrivateKey privateKey =
          keyService.loadPrivateKey(openPrivateKey(), publicKey.getKeyID(), "test".toCharArray());
      char[] passphrase = "test".toCharArray();
      DecryptionService decryptionService = new DecryptionService(mockedKeyService);
      when(mockedKeyService.loadPrivateKey(
              any(InputStream.class), eq(publicKey.getKeyID()), same(passphrase)))
          .thenReturn(privateKey);

      ByteArrayOutputStream output = new ByteArrayOutputStream();
      decryptionService.decrypt(
          new ByteArrayInputStream(encrypted), output, openPrivateKey(), passphrase);

      assertThat(output.toString(StandardCharsets.UTF_8)).isEqualTo(readExampleText());
      verify(mockedKeyService)
          .loadPrivateKey(any(InputStream.class), eq(publicKey.getKeyID()), same(passphrase));
    }

    @Test
    @DisplayName("Should reject input with no encrypted data")
    void shouldRejectInputWithNoEncryptedData() {
      DecryptionService decryptionService = new DecryptionService(keyService);

      assertThatThrownBy(
              () ->
                  decryptionService.decrypt(
                      new ByteArrayInputStream(new byte[0]),
                      new ByteArrayOutputStream(),
                      openPrivateKey(),
                      "test".toCharArray()))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessage("No encrypted data found in input stream");
    }

    @Test
    @DisplayName("Should reject encrypted data list without public-key packet")
    void shouldRejectEncryptedDataListWithoutPublicKeyPacket() throws Exception {
      DecryptionService decryptionService = new DecryptionService(keyService);
      PGPEncryptedDataList encryptedDataList = mock(PGPEncryptedDataList.class);
      PGPEncryptedData encryptedData = mock(PGPEncryptedData.class);
      when(encryptedDataList.getEncryptedDataObjects())
          .thenReturn(List.of(encryptedData).iterator());

      Method method =
          DecryptionService.class.getDeclaredMethod(
              "findPublicKeyEncryptedData", PGPEncryptedDataList.class);
      method.setAccessible(true);

      assertThatThrownBy(() -> invokePrivate(method, decryptionService, encryptedDataList))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessage("No public-key encrypted data found in input stream");
    }

    @Test
    @DisplayName("Should reject payload when integrity check fails")
    void shouldRejectPayloadWhenIntegrityCheckFails() throws Exception {
      DecryptionService decryptionService = new DecryptionService(keyService);
      PGPPublicKeyEncryptedData encryptedData = mock(PGPPublicKeyEncryptedData.class);
      PGPPrivateKey privateKey = mock(PGPPrivateKey.class);
      when(encryptedData.getDataStream(any(PublicKeyDataDecryptorFactory.class)))
          .thenReturn(new ByteArrayInputStream("plain".getBytes(StandardCharsets.UTF_8)));
      when(encryptedData.isIntegrityProtected()).thenReturn(true);
      when(encryptedData.verify()).thenReturn(false);

      Method method =
          DecryptionService.class.getDeclaredMethod(
              "decrypt", PGPPublicKeyEncryptedData.class, OutputStream.class, PGPPrivateKey.class);
      method.setAccessible(true);

      assertThatThrownBy(
              () ->
                  invokePrivate(
                      method,
                      decryptionService,
                      encryptedData,
                      new ByteArrayOutputStream(),
                      privateKey))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessage("PGP message integrity check failed");
    }
  }

  private PGPPublicKey loadPublicKey() throws Exception {
    try (InputStream publicKeyStream = Files.newInputStream(PUBLIC_KEY_PATH)) {
      return keyService.loadPublicKey(publicKeyStream);
    }
  }

  private InputStream openPrivateKey() throws Exception {
    return Files.newInputStream(PRIVATE_KEY_PATH);
  }

  private byte[] encryptExampleText() throws Exception {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    encryptionService.encrypt(
        new ByteArrayInputStream(readExampleText().getBytes(StandardCharsets.UTF_8)),
        output,
        loadPublicKey());
    return output.toByteArray();
  }

  private String readExampleText() throws Exception {
    return Files.readString(PLAIN_TEXT_PATH);
  }

  private Object invokePrivate(Method method, Object target, Object... args) throws Throwable {
    try {
      return method.invoke(target, args);
    } catch (InvocationTargetException exception) {
      throw exception.getCause();
    }
  }
}
