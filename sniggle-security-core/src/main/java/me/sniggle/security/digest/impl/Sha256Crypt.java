package me.sniggle.security.digest.impl;

import me.sniggle.security.crypto.config.RoundConfiguration;
import me.sniggle.security.digest.config.Algorithm;

/**
 * The class implementing SHA-256 CRYPT specific parts of the algorithm, meaning
 * the input buffer length and the algorithm to build the final hash string
 * 
 * @author iulius
 * @since 0.0.1
 * 
 */
public class Sha256Crypt extends ShaCrypt {

  /**
   * the default constructor
   */
  public Sha256Crypt() {
    super(Algorithm.SHA256_CRYPT);
  }

  /**
   * constructor
   * 
   * @param config
   *          the configuration of rounds/iteration ranges to be used
   */
  public Sha256Crypt(RoundConfiguration config) {
    super(Algorithm.SHA256_CRYPT, config);
  }


  /*
   * (non-Javadoc)
   * 
   * @see me.sniggle.security.digest.impl.ShaCrypt#getInputBufferLength()
   */
  @Override
  protected int getInputBufferLength() {
    return 32;
  }

  /*
   * (non-Javadoc)
   * 
   * @see me.sniggle.security.digest.impl.ShaCrypt#appendBase64OfHash(java.lang.
   * StringBuffer, byte[])
   */
  @Override
  protected void appendBase64OfHash(StringBuffer result, byte[] finalHash) {
    result.append(createBase64EncodedStringFrom3bytes(finalHash[0], finalHash[10], finalHash[20], 4));
    result.append(createBase64EncodedStringFrom3bytes(finalHash[21], finalHash[1], finalHash[11], 4));
    result.append(createBase64EncodedStringFrom3bytes(finalHash[12], finalHash[22], finalHash[2], 4));
    result.append(createBase64EncodedStringFrom3bytes(finalHash[3], finalHash[13], finalHash[23], 4));
    result.append(createBase64EncodedStringFrom3bytes(finalHash[24], finalHash[4], finalHash[14], 4));
    result.append(createBase64EncodedStringFrom3bytes(finalHash[15], finalHash[25], finalHash[5], 4));
    result.append(createBase64EncodedStringFrom3bytes(finalHash[6], finalHash[16], finalHash[26], 4));
    result.append(createBase64EncodedStringFrom3bytes(finalHash[27], finalHash[7], finalHash[17], 4));
    result.append(createBase64EncodedStringFrom3bytes(finalHash[18], finalHash[28], finalHash[8], 4));
    result.append(createBase64EncodedStringFrom3bytes(finalHash[9], finalHash[19], finalHash[29], 4));
    result.append(createBase64EncodedStringFrom3bytes((byte) 0x00, finalHash[31], finalHash[30], 3));
  }
  
}
