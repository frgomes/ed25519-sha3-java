package jp.co.soramitsu.crypto.ed25519;

import static jp.co.soramitsu.crypto.ed25519.EdDSAEngine.ONE_SHOT_MODE;
import static jp.co.soramitsu.crypto.ed25519.spec.EdDSANamedCurveTable.ED_25519;

import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import jp.co.soramitsu.crypto.ed25519.spec.EdDSANamedCurveTable;
import jp.co.soramitsu.crypto.ed25519.spec.EdDSAParameterSpec;
import jp.co.soramitsu.crypto.ed25519.spec.EdDSAPrivateKeySpec;
import jp.co.soramitsu.crypto.ed25519.spec.EdDSAPublicKeySpec;

public class Ed25519Sha3 {

  public static final EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(ED_25519);

  static {
    Security.addProvider(new EdDSASecurityProvider());
  }

  private EdDSAEngine sgr;
  private KeyPairGenerator keyGen;


  public Ed25519Sha3() {
    try {
      this.keyGen = new KeyPairGenerator();
      this.sgr = new EdDSAEngine(
          MessageDigest.getInstance(
              spec.getHashAlgorithm()
          )
      );
    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }

  public static KeyPair keyPairFromBytes(byte[] privateKey, byte[] publicKey) {
    return new KeyPair(
        publicKeyFromBytes(publicKey),
        privateKeyFromBytes(privateKey)
    );
  }

  public static PublicKey publicKeyFromBytes(byte[] publicKey) {
    return new EdDSAPublicKey(new EdDSAPublicKeySpec(publicKey, spec));
  }

  public static PrivateKey privateKeyFromBytes(byte[] privateKey) {
    return new EdDSAPrivateKey(new EdDSAPrivateKeySpec(privateKey, spec));
  }

  public static byte[] publicKeyToBytes(PublicKey pub) {
    if (!(pub instanceof EdDSAPublicKey)) {
      throw new IllegalArgumentException("publicKeyToBytes: pub is not instanceof EdDSAPublicKey");
    }

    return ((EdDSAPublicKey) pub).getAbyte();
  }

  public static byte[] privateKeyToBytes(PrivateKey priv) {
    if (!(priv instanceof EdDSAPrivateKey)) {
      throw new IllegalArgumentException(
          "privateKeyToBytes: priv is not instanceof EdDSAPrivateKey");
    }

    return ((EdDSAPrivateKey) priv).getSeed();
  }

  public byte[] rawSign(byte[] data, KeyPair keypair) {
    try {
      sgr.initSign(keypair.getPrivate());
      sgr.setParameter(ONE_SHOT_MODE);
      sgr.update(data);
      return sgr.sign();
    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }

  public boolean rawVerify(byte[] data, byte[] signature, PublicKey publicKey) {
    try {
      sgr.initVerify(publicKey);
      sgr.setParameter(ONE_SHOT_MODE);
      sgr.update(data);
      return sgr.verify(signature);
    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }

  public KeyPair generateKeypair() {
    try {
      return keyGen.generateKeyPair();
    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }

  public KeyPair generateKeypair(byte[] seed) {
    try {
      EdDSAPrivateKeySpec privKey = new EdDSAPrivateKeySpec(seed, spec);
      EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(privKey.getA(), spec);

      return new KeyPair(
          new EdDSAPublicKey(pubKey),
          new EdDSAPrivateKey(privKey)
      );

    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }

  public static class CryptoException extends RuntimeException {

    CryptoException(Exception e) {
      super(e);
    }
  }

}
