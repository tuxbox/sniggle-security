/**
 * 
 */
package me.sniggle.security.salt.impl;

import me.sniggle.security.salt.SaltProvider;

/**
 * This class implements a fixed salt provider in order to create a predictable
 * hash (e.g. for verfication of a plain text)
 * 
 * @author iulius
 * @since 0.0.1
 * 
 */
public class FixedSaltProvider implements SaltProvider {

  private final String salt;

  /**
   * 
   * @param salt
   *          the salt to be provisioned
   */
  public FixedSaltProvider(String salt) {
    super();
    this.salt = salt;
  }

  /* (non-Javadoc)
   * @see org.jasypt.salt.SaltGenerator#generateSalt(int)
   */
  @Override
  public byte[] generateSalt(int lengthBytes) {
    return salt.getBytes();
  }

  /* (non-Javadoc)
   * @see org.jasypt.salt.SaltGenerator#includePlainSaltInEncryptionResults()
   */
  @Override
  public boolean includePlainSaltInEncryptionResults() {
    return false;
  }

  /* (non-Javadoc)
   * @see me.sniggle.security.salt.SaltProvider#getSaltString()
   */
  @Override
  public String getSaltString() {
    return salt;
  }

  /* (non-Javadoc)
   * @see me.sniggle.security.salt.SaltProvider#getLastGeneratedSalt()
   */
  @Override
  public String getLastGeneratedSalt() {
    return getSaltString();
  }

}
