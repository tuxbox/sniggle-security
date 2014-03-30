/**
 * 
 */
package me.sniggle.security.crypto.impl;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import me.sniggle.security.crypto.config.SecurityLevel;

/**
 * @author iulius
 *
 */
public class BouncyCastleAsymetricKeyGenerator extends AsymetricKeyGenerator {

  /**
   * @param securityLevel
   * @param provider
   */
  public BouncyCastleAsymetricKeyGenerator(SecurityLevel securityLevel) {
    super(securityLevel, "BC");
    // TODO Auto-generated constructor stub
  }

  /* (non-Javadoc)
   * @see me.sniggle.security.crypto.impl.AsymetricKeyGenerator#initializeSecurityProvider()
   */
  @Override
  protected boolean initializeSecurityProvider() {
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
    return false;
  }

}
