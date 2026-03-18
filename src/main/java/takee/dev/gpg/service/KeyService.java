package takee.dev.gpg.service;

import java.io.InputStream;
import lombok.SneakyThrows;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.springframework.stereotype.Service;

@Service
public class KeyService {

  @SneakyThrows
  public PGPPublicKey loadPublicKey(InputStream inputStream) {
    PGPPublicKeyRingCollection keyRing =
        new PGPPublicKeyRingCollection(
            PGPUtil.getDecoderStream(inputStream), new JcaKeyFingerprintCalculator());
    return keyRing.getKeyRings().next().getPublicKeys().next();
  }

  @SneakyThrows
  public PGPPrivateKey loadPrivateKey(InputStream privateKeyStream, char[] passphrase) {

    PGPSecretKeyRingCollection secretKeyRings =
        new PGPSecretKeyRingCollection(
            PGPUtil.getDecoderStream(privateKeyStream), new JcaKeyFingerprintCalculator());

    PGPSecretKey secretKey = secretKeyRings.getKeyRings().next().getSecretKeys().next();

    return secretKey.extractPrivateKey(
        new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passphrase));
  }
}
