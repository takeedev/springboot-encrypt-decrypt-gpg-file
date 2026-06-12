package takee.dev.gpg.service;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Objects;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.springframework.stereotype.Service;

@Service
public class KeyService {

  public PGPPublicKey loadPublicKey(InputStream inputStream) throws IOException, PGPException {
    Objects.requireNonNull(inputStream, "Public key input stream must not be null");

    PGPPublicKeyRingCollection keyRings =
        new PGPPublicKeyRingCollection(
            PGPUtil.getDecoderStream(inputStream), new JcaKeyFingerprintCalculator());

    Iterator<PGPPublicKeyRing> publicKeyRings = keyRings.getKeyRings();
    while (publicKeyRings.hasNext()) {
      Iterator<PGPPublicKey> publicKeys = publicKeyRings.next().getPublicKeys();
      while (publicKeys.hasNext()) {
        PGPPublicKey publicKey = publicKeys.next();
        if (publicKey.isEncryptionKey()) {
          return publicKey;
        }
      }
    }

    throw new IllegalArgumentException("No encryption-capable public key found");
  }

  public PGPPrivateKey loadPrivateKey(InputStream privateKeyStream, long keyId, char[] passphrase)
      throws IOException, PGPException {
    Objects.requireNonNull(privateKeyStream, "Private key input stream must not be null");
    Objects.requireNonNull(passphrase, "Passphrase must not be null");

    PGPSecretKeyRingCollection secretKeyRings =
        new PGPSecretKeyRingCollection(
            PGPUtil.getDecoderStream(privateKeyStream), new JcaKeyFingerprintCalculator());

    PGPSecretKey secretKey = secretKeyRings.getSecretKey(keyId);
    if (secretKey == null || secretKey.isPrivateKeyEmpty()) {
      throw new IllegalArgumentException(
          "No private key found for key ID " + Long.toHexString(keyId));
    }

    return extractPrivateKey(secretKey, passphrase);
  }

  private PGPPrivateKey extractPrivateKey(PGPSecretKey secretKey, char[] passphrase)
      throws PGPException {
    try {
      PGPPrivateKey privateKey =
          secretKey.extractPrivateKey(
              new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passphrase));
      if (privateKey == null) {
        throw new IllegalArgumentException(
            "Unable to extract private key " + Long.toHexString(secretKey.getKeyID()));
      }
      return privateKey;
    } finally {
      Arrays.fill(passphrase, '\0');
    }
  }
}
