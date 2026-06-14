package takee.dev.gpg.service;

import static org.assertj.core.api.Assertions.assertThat;
import static takee.dev.gpg.service.GpgTestFixtures.loadPublicKey;
import static takee.dev.gpg.service.GpgTestFixtures.readExampleText;
import static takee.dev.gpg.service.GpgTestFixtures.readExampleTextBytes;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class EncryptionServiceTest {

  private final KeyService keyService = new KeyService();
  private final EncryptionService encryptionService = new EncryptionService();

  @BeforeAll
  static void setUpProvider() {
    GpgTestFixtures.setUpProvider();
  }

  @Test
  @DisplayName("Should encrypt plaintext into PGP payload")
  void shouldEncryptPlaintextIntoPgpPayload() throws Exception {
    ByteArrayOutputStream output = new ByteArrayOutputStream();

    encryptionService.encrypt(
        new ByteArrayInputStream(readExampleTextBytes()), output, loadPublicKey(keyService));

    byte[] encrypted = output.toByteArray();
    assertThat(encrypted).isNotEmpty();
    assertThat(new String(encrypted, StandardCharsets.UTF_8)).doesNotContain(readExampleText());
  }
}
