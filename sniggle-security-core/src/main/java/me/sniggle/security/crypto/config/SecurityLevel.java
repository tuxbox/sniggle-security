package me.sniggle.security.crypto.config;

/**
 * the enumeration provides a mapping between the required security level and
 * the key size in bits
 * 
 * @author iulius
 * @since 0.0.1
 * 
 */
public enum SecurityLevel {
  MEDIUM(2048),
  SECURE(4096),
  SUPER_SECURE(8192);

  private int keyLength;

  private SecurityLevel(int keyLength) {
    this.keyLength = keyLength;
  }

  /**
   * 
   * @return the key size in bits, e.g. 2048 for a 2048bit key
   */
  public int keyLength() {
    return keyLength;
  }
}
