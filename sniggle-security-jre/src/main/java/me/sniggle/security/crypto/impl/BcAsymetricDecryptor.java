package me.sniggle.security.crypto.impl;

import java.security.Security;

import me.sniggle.security.crypto.config.Algorithm;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * A simple helper class to decrypt asymmetrically encrypted data using the
 * private key
 * 
 * @author iulius
 * @since 0.0.1
 * 
 */
public class BcAsymetricDecryptor extends BaseDecryptor {

  /**
   * constructor
   * 
   * @param algorithm
   *          the supported algorithm to be used as specified in
   *          {@link Algorithm}, may not be null
   */
  public BcAsymetricDecryptor(Algorithm algorithm) {
    super(algorithm, "BC");
  }

  @Override
  protected void addSecurityProvider() {
    Security.insertProviderAt(new BouncyCastleProvider(), 1);

  }

}
