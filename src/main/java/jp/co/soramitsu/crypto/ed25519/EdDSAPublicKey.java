package jp.co.soramitsu.crypto.ed25519;

import java.security.PublicKey;
import jp.co.soramitsu.crypto.ed25519.math.GroupElement;
import jp.co.soramitsu.crypto.ed25519.spec.EdDSAParameterSpec;
import jp.co.soramitsu.crypto.ed25519.spec.EdDSAPublicKeySpec;

/**
 * An EdDSA public key.
 */
public class EdDSAPublicKey implements EdDSAKey, PublicKey {

  private static final long serialVersionUID = 9837459837498475L;
  private final GroupElement A;
  private final byte[] Abyte;
  private final EdDSAParameterSpec params;
  private GroupElement Aneg = null;

  public EdDSAPublicKey(EdDSAPublicKeySpec spec) {
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

  @Override
  public byte[] getEncoded() {
    return this.Abyte;
  }

  public GroupElement getNegativeA() {
    // Only read Aneg once, otherwise read re-ordering might occur between here and return. Requires all GroupElement's fields to be final.
    GroupElement ourAneg = Aneg;
    if (ourAneg == null) {
      ourAneg = A.negate();
      Aneg = ourAneg;
    }
    return ourAneg;
  }

  public jp.co.soramitsu.crypto.ed25519.math.GroupElement getA() {
    return A;
  }

  public byte[] getAbyte() {
    return Abyte;
  }

  public jp.co.soramitsu.crypto.ed25519.math.GroupElement getAneg() {
    return Aneg;
  }

  @Override
  public jp.co.soramitsu.crypto.ed25519.spec.EdDSAParameterSpec getParams() {
    return params;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    jp.co.soramitsu.crypto.ed25519.EdDSAPublicKey that = (jp.co.soramitsu.crypto.ed25519.EdDSAPublicKey) o;
    return java.util.Objects.equals(A, that.A) &&
            java.util.Arrays.equals(Abyte, that.Abyte) &&
            java.util.Objects.equals(params, that.params) &&
            java.util.Objects.equals(Aneg, that.Aneg);
  }

  @Override
  public int hashCode() {
    int result = java.util.Objects.hash(A, params, Aneg);
    result = 31 * result + java.util.Arrays.hashCode(Abyte);
    return result;
  }
}
