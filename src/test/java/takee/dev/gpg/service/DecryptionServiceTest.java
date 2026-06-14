package takee.dev.gpg.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.same;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static takee.dev.gpg.service.GpgTestFixtures.loadPublicKey;
import static takee.dev.gpg.service.GpgTestFixtures.openPrivateKey;
import static takee.dev.gpg.service.GpgTestFixtures.readExampleText;
import static takee.dev.gpg.service.GpgTestFixtures.readExampleTextBytes;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class DecryptionServiceTest {

  private final KeyService keyService = new KeyService();
  private final EncryptionService encryptionService = new EncryptionService();

  @Mock private KeyService mockedKeyService;

  @BeforeAll
  static void setUpProvider() {
    GpgTestFixtures.setUpProvider();
  }

  @Test
  @DisplayName("Should decrypt encrypted payload with private key selected by packet key ID")
  void shouldDecryptEncryptedPayloadWithPrivateKeySelectedByPacketKeyId() throws Exception {
    byte[] encrypted = encryptExampleText();
    PGPPublicKey publicKey = loadPublicKey(keyService);
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
    when(encryptedDataList.getEncryptedDataObjects()).thenReturn(List.of(encryptedData).iterator());

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

  private byte[] encryptExampleText() throws Exception {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    encryptionService.encrypt(
        new ByteArrayInputStream(readExampleTextBytes()), output, loadPublicKey(keyService));
    return output.toByteArray();
  }

  private Object invokePrivate(Method method, Object target, Object... args) throws Throwable {
    try {
      return method.invoke(target, args);
    } catch (InvocationTargetException exception) {
      throw exception.getCause();
    }
  }
}
