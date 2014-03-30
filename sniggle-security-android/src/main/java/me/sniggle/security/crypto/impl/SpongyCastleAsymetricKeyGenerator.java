/**
 * 
 */
package me.sniggle.security.crypto.impl;

import java.security.Security;
import org.spongycastle.jce.provider.BouncyCastleProvider;

import me.sniggle.security.crypto.config.SecurityLevel;

/**
 * @author iulius
 *
 */
public class SpongyCastleAsymetricKeyGenerator extends AsymetricKeyGenerator {

  /**
   * @param securityLevel
   * @param provider
   */
  public SpongyCastleAsymetricKeyGenerator(SecurityLevel securityLevel) {
    super(securityLevel, "SC");
  }

  /* (non-Javadoc)
   * @see me.sniggle.security.crypto.impl.AsymetricKeyGenerator#initializeSecurityProvider()
   */
  @Override
  protected boolean initializeSecurityProvider() {
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
    return true;
  }

}
