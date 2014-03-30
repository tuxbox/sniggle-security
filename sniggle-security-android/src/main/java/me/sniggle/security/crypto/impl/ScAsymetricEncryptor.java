/**
 * 
 */
package me.sniggle.security.crypto.impl;

import java.security.Security;

import me.sniggle.security.crypto.config.Algorithm;

import org.spongycastle.jce.provider.BouncyCastleProvider;

/**
 * this class provides an easy API to encrypt data using a public key
 * 
 * @author iulius
 * @since 0.0.1
 * 
 */
public class ScAsymetricEncryptor extends BaseEncryptor {

  /**
   * 
   * @param algorithm
   *          the supported {@link Algorithm}, may not be null
   */
  public ScAsymetricEncryptor(Algorithm algorithm) {
    super(algorithm, "SC");
  }

  /*
   * (non-Javadoc)
   * 
   * @see me.sniggle.security.crypto.impl.BaseCryptor#addSecurityProvider()
   */
  @Override
  protected void addSecurityProvider() {
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
  }

}
