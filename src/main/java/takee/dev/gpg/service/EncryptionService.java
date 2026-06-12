package takee.dev.gpg.service;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.springframework.stereotype.Service;

@Service
public class EncryptionService {

  public void encrypt(InputStream input, OutputStream output, PGPPublicKey publicKey)
      throws IOException, PGPException {

    PGPEncryptedDataGenerator encGen =
        new PGPEncryptedDataGenerator(
            new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256)
                .setWithIntegrityPacket(true)
                .setSecureRandom(new SecureRandom())
                .setProvider("BC"));

    encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider("BC"));

    try (OutputStream encryptedOut = encGen.open(output, new byte[1 << 16])) {
      input.transferTo(encryptedOut);
    }
  }
}
