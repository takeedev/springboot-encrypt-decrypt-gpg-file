package takee.dev.gpg.service;

import java.io.InputStream;
import java.io.OutputStream;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class DecryptionService {

  @SneakyThrows
  public void decrypt(InputStream encryptedInput, OutputStream output, PGPPrivateKey privateKey) {

    PGPObjectFactory factory =
        new PGPObjectFactory(
            PGPUtil.getDecoderStream(encryptedInput), new JcaKeyFingerprintCalculator());

    Object object = factory.nextObject();

    if (object instanceof PGPEncryptedDataList encList) {

      PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData) encList.get(0);

      InputStream clear =
          encData.getDataStream(
              new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privateKey));

      clear.transferTo(output);
    }
  }
}
