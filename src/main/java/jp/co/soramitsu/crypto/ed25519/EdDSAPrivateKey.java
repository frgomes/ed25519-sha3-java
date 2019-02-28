package jp.co.soramitsu.crypto.ed25519;

import java.security.PrivateKey;
import jp.co.soramitsu.crypto.ed25519.math.GroupElement;
import jp.co.soramitsu.crypto.ed25519.spec.EdDSAParameterSpec;
import jp.co.soramitsu.crypto.ed25519.spec.EdDSAPrivateKeySpec;

/**
 * An EdDSA private key.
 */
public class EdDSAPrivateKey implements EdDSAKey, PrivateKey {

  private static final long serialVersionUID = 23495873459878957L;
  private final byte[] seed;  // will be null if constructed from a spec which was directly constructed from H
  private final byte[] h;  // the hash of the seed
  private final byte[] a;  // the private key
  private final GroupElement A;  // the public key
  private final byte[] Abyte;  // the public key
  private final EdDSAParameterSpec params;

  public EdDSAPrivateKey(EdDSAPrivateKeySpec spec) {
    this.seed = spec.getSeed();
    this.h = spec.getH();
    this.a = spec.geta();
    this.A = spec.getA();
    this.Abyte = this.A.toByteArray();
    this.params = spec.getParams();
  }

  @Override
  public String getAlgorithm() {
    return KEY_ALGORITHM;
  }

  @Override
  public String getFormat() {
    return "RAW";
  }

  public byte[] geta() {
    return a;
  }

  public GroupElement getA() {
    return this.A;
  }

  @Override
  public byte[] getEncoded() {
    return seed;
  }

  public byte[] getSeed() {
    return seed;
  }

  public byte[] getH() {
    return h;
  }

  public byte[] getAbyte() {
    return Abyte;
  }

  @Override
  public jp.co.soramitsu.crypto.ed25519.spec.EdDSAParameterSpec getParams() {
    return params;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    jp.co.soramitsu.crypto.ed25519.EdDSAPrivateKey that = (jp.co.soramitsu.crypto.ed25519.EdDSAPrivateKey) o;
    return java.util.Arrays.equals(seed, that.seed) &&
            java.util.Arrays.equals(h, that.h) &&
            java.util.Arrays.equals(a, that.a) &&
            java.util.Objects.equals(A, that.A) &&
            java.util.Arrays.equals(Abyte, that.Abyte) &&
            java.util.Objects.equals(params, that.params);
  }

  @Override
  public int hashCode() {
    int result = java.util.Objects.hash(A, params);
    result = 31 * result + java.util.Arrays.hashCode(seed);
    result = 31 * result + java.util.Arrays.hashCode(h);
    result = 31 * result + java.util.Arrays.hashCode(a);
    result = 31 * result + java.util.Arrays.hashCode(Abyte);
    return result;
  }
}
