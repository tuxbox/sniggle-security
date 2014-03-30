package me.sniggle.security.digest.impl;

import me.sniggle.security.crypto.config.RoundConfiguration;
import me.sniggle.security.digest.config.Algorithm;

/**
 * This class implements the Sha512 CRYPT specific parts of the algrithm, namely
 * the input buffer length and the creation of the final hash
 * 
 * @author iulius
 * @since 0.0.1
 * 
 */
public class Sha512Crypt extends ShaCrypt {

  /**
   * the default constructor
   */
  public Sha512Crypt() {
    super(Algorithm.SHA512_CRYPT);
  }

  /**
   * 
   * @param roundConfiguration
   *          the configuration of round/iteration ranges to be used
   */
  public Sha512Crypt(RoundConfiguration roundConfiguration) {
    super(Algorithm.SHA512_CRYPT, roundConfiguration);
  }

  /*
   * (non-Javadoc)
   * 
   * @see me.sniggle.security.digest.impl.ShaCrypt#getInputBufferLength()
   */
  @Override
  protected int getInputBufferLength() {
    return 64;
  }

  /*
   * (non-Javadoc)
   * 
   * @see me.sniggle.security.digest.impl.ShaCrypt#appendBase64OfHash(java.lang.
   * StringBuffer, byte[])
   */
  @Override
  protected void appendBase64OfHash(StringBuffer result, byte[] finalHash) {
    result.append(createBase64EncodedStringFrom3bytes(finalHash[0], finalHash[21], finalHash[42], 4));
    result.append(createBase64EncodedStringFrom3bytes(finalHash[22], finalHash[43], finalHash[1], 4));
    result.append(createBase64EncodedStringFrom3bytes(finalHash[44], finalHash[2], finalHash[23], 4));
    result.append(createBase64EncodedStringFrom3bytes(finalHash[3], finalHash[24], finalHash[45], 4));
    result.append(createBase64EncodedStringFrom3bytes(finalHash[25], finalHash[46], finalHash[4], 4));
    result.append(createBase64EncodedStringFrom3bytes(finalHash[47], finalHash[5], finalHash[26], 4));
    result.append(createBase64EncodedStringFrom3bytes(finalHash[6], finalHash[27], finalHash[48], 4));
    result.append(createBase64EncodedStringFrom3bytes(finalHash[28], finalHash[49], finalHash[7], 4));
    result.append(createBase64EncodedStringFrom3bytes(finalHash[50], finalHash[8], finalHash[29], 4));
    result.append(createBase64EncodedStringFrom3bytes(finalHash[9], finalHash[30], finalHash[51], 4));
    result.append(createBase64EncodedStringFrom3bytes(finalHash[31], finalHash[52], finalHash[10], 4));
    result.append(createBase64EncodedStringFrom3bytes(finalHash[53], finalHash[11], finalHash[32], 4));
    result.append(createBase64EncodedStringFrom3bytes(finalHash[12], finalHash[33], finalHash[54], 4));
    result.append(createBase64EncodedStringFrom3bytes(finalHash[34], finalHash[55], finalHash[13], 4));
    result.append(createBase64EncodedStringFrom3bytes(finalHash[56], finalHash[14], finalHash[35], 4));
    result.append(createBase64EncodedStringFrom3bytes(finalHash[15], finalHash[36], finalHash[57], 4));
    result.append(createBase64EncodedStringFrom3bytes(finalHash[37], finalHash[58], finalHash[16], 4));
    result.append(createBase64EncodedStringFrom3bytes(finalHash[59], finalHash[17], finalHash[38], 4));
    result.append(createBase64EncodedStringFrom3bytes(finalHash[18], finalHash[39], finalHash[60], 4));
    result.append(createBase64EncodedStringFrom3bytes(finalHash[40], finalHash[61], finalHash[19], 4));
    result.append(createBase64EncodedStringFrom3bytes(finalHash[62], finalHash[20], finalHash[41], 4));
    result.append(createBase64EncodedStringFrom3bytes((byte) 0x00, (byte) 0x00, finalHash[63], 2));
  }

}
