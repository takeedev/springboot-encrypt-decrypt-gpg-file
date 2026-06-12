package takee.dev.gpg;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import lombok.SneakyThrows;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import takee.dev.gpg.service.DecryptionService;
import takee.dev.gpg.service.EncryptionService;
import takee.dev.gpg.service.KeyService;

@SpringBootTest
class GpgApplicationTests {

  @Autowired private KeyService keyService;

  @Autowired private EncryptionService encryptionService;

  @Autowired private DecryptionService decryptionService;

  @Test
  @SneakyThrows
  @DisplayName("Should Encrypt File Successfully")
  void shouldEncryptFileSuccessfully() {
    var inputStreamKey = new FileInputStream("src/main/resources/keys/public_key.asc");
    var pathFile = new FileInputStream("src/test/java/resource/example.txt");
    var pgpPublicKey = keyService.loadPublicKey(inputStreamKey);
    var outputStream = new FileOutputStream("example.txt.pgp");
    encryptionService.encrypt(pathFile, outputStream, pgpPublicKey);
  }

  @Test
  @SneakyThrows
  @DisplayName("Should Decrypt File Success")
  void shouldDecryptFileSuccess() {
    try (var privateKeyStream = new FileInputStream("src/main/resources/keys/private_key.asc");
        var encryptedFile = new FileInputStream("example.txt.pgp");
        var outputStream = new FileOutputStream("test.txt")) {
      var charsPassphrase = "test".toCharArray();
      decryptionService.decrypt(encryptedFile, outputStream, privateKeyStream, charsPassphrase);
    }
  }
}
