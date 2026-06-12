package takee.dev.gpg.service;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Iterator;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
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

  private final KeyService keyService;

  public void decrypt(
      InputStream encryptedInput,
      OutputStream output,
      InputStream privateKeyStream,
      char[] passphrase)
      throws IOException, PGPException {

    PGPPublicKeyEncryptedData encData = readPublicKeyEncryptedData(encryptedInput);
    PGPPrivateKey privateKey =
        keyService.loadPrivateKey(
            privateKeyStream, encData.getKeyIdentifier().getKeyId(), passphrase);

    decrypt(encData, output, privateKey);
  }

  private PGPPublicKeyEncryptedData readPublicKeyEncryptedData(InputStream encryptedInput)
      throws IOException {
    PGPObjectFactory factory =
        new PGPObjectFactory(
            PGPUtil.getDecoderStream(encryptedInput), new JcaKeyFingerprintCalculator());

    Object object = factory.nextObject();
    if (!(object instanceof PGPEncryptedDataList)) {
      object = factory.nextObject();
    }

    if (!(object instanceof PGPEncryptedDataList encList)) {
      throw new IllegalArgumentException("No encrypted data found in input stream");
    }

    return findPublicKeyEncryptedData(encList);
  }

  private void decrypt(
      PGPPublicKeyEncryptedData encData, OutputStream output, PGPPrivateKey privateKey)
      throws IOException, PGPException {
    try (InputStream clear =
        encData.getDataStream(
            new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privateKey))) {
      clear.transferTo(output);
    }

    if (encData.isIntegrityProtected() && !encData.verify()) {
      throw new IllegalArgumentException("PGP message integrity check failed");
    }
  }

  private PGPPublicKeyEncryptedData findPublicKeyEncryptedData(PGPEncryptedDataList encList) {
    Iterator<PGPEncryptedData> encryptedDataObjects = encList.getEncryptedDataObjects();
    while (encryptedDataObjects.hasNext()) {
      PGPEncryptedData encryptedData = encryptedDataObjects.next();
      if (encryptedData instanceof PGPPublicKeyEncryptedData publicKeyEncryptedData) {
        return publicKeyEncryptedData;
      }
    }

    throw new IllegalArgumentException("No public-key encrypted data found in input stream");
  }
}
