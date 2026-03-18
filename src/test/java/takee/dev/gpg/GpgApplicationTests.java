package takee.dev.gpg;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Path;
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

  Path tempPath;

  @Test
  @SneakyThrows
  @DisplayName("Should Encrypt File Successfully")
  void shouldEncryptFileSuccessfully() {
    var inputStream = new FileInputStream("src/main/resources/keys/public_key.asc");
    var pathFile = new FileInputStream("src/test/java/resource/example.txt");
    var key = keyService.loadPublicKey(inputStream);
    var outputStream = new FileOutputStream("example.txt.pgp");
    System.out.println(tempPath);
    encryptionService.encrypt(pathFile, outputStream, key);
  }

  @Test
  @SneakyThrows
  @DisplayName("Should Decrypt File Success")
  void shouldDecryptFileSuccess() {
    var inputStream = new FileInputStream("src/main/resources/keys/private_key.asc");
    var pathFile = new FileInputStream("example.txt.pgp");
    var stringPassphrase = "test";
    var charsPassphrase = stringPassphrase.toCharArray();
    var key = keyService.loadPrivateKey(inputStream, charsPassphrase);
    var outputStream = new FileOutputStream("test.txt");
    decryptionService.decrypt(pathFile, outputStream, key);
  }
}
