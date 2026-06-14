package takee.dev.gpg.service;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.bouncycastle.openpgp.PGPPublicKey;
import takee.dev.gpg.config.BouncyCastleConfig;

final class GpgTestFixtures {

  static final Path PUBLIC_KEY_PATH = Path.of("src/main/resources/keys/public_key.asc");
  static final Path PRIVATE_KEY_PATH = Path.of("src/main/resources/keys/private_key.asc");
  static final Path PLAIN_TEXT_PATH = Path.of("src/test/java/resource/example.txt");

  private GpgTestFixtures() {}

  static void setUpProvider() {
    new BouncyCastleConfig();
  }

  static PGPPublicKey loadPublicKey(KeyService keyService) throws Exception {
    try (InputStream publicKeyStream = Files.newInputStream(PUBLIC_KEY_PATH)) {
      return keyService.loadPublicKey(publicKeyStream);
    }
  }

  static InputStream openPrivateKey() throws Exception {
    return Files.newInputStream(PRIVATE_KEY_PATH);
  }

  static String readExampleText() throws Exception {
    return Files.readString(PLAIN_TEXT_PATH);
  }

  static byte[] readExampleTextBytes() throws Exception {
    return readExampleText().getBytes(StandardCharsets.UTF_8);
  }
}
