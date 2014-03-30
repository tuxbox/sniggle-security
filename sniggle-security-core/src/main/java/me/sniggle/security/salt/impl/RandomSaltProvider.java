package me.sniggle.security.salt.impl;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;

import me.sniggle.security.salt.SaltProvider;

/**
 * creates a salt string according to the reference implementation of
 * SHA-256/512-CRYPT
 * 
 * @author iulius
 * @since 0.0.1
 * 
 */
public class RandomSaltProvider implements SaltProvider {

  private static final char[] SALTCHARS = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
      'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
      'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0' };
  private final int minSaltLength;
  private final int maxSaltLength;
  private String lastGeneratedSalt;

  /**
   * constructor
   * 
   * @param minSaltLength
   *          the minimum salt length required
   * @param maxSaltLength
   *          the maximum salt length allowed
   */
  public RandomSaltProvider(int minSaltLength, int maxSaltLength) {
    super();
    this.minSaltLength = minSaltLength;
    this.maxSaltLength = maxSaltLength;
  }

  /**
   * creates a salt using the {@link #SALTCHARS} array and {@link SecureRandom}
   * within the minimum (incl.) and maximum (incl.) salt length
   * 
   * @param minLength
   *          the minimum salt length required
   * @param maxLength
   *          the maximum salt length allowed
   * @return an appropriate salt
   */
  private String createSalt(int minLength, int maxLength) {
    StringBuffer salt = new StringBuffer();
    SecureRandom random = new SecureRandom();
    int length;
    if (maxLength > minLength) {
      length = random.nextInt(maxLength - minLength) + minLength;
    } else {
      length = (minLength < minSaltLength) ? minSaltLength : (maxLength > maxSaltLength) ? maxSaltLength : minLength;
    }
    while (salt.length() < length) {
      int index = (int) (random.nextDouble() * SALTCHARS.length);
      salt.append(SALTCHARS[index]);
    }
    return salt.toString();
  }

  /* (non-Javadoc)
   * @see org.jasypt.salt.SaltGenerator#generateSalt(int)
   */
  @Override
  public byte[] generateSalt(int lengthBytes) {
    try {
      lastGeneratedSalt = createSalt(lengthBytes, lengthBytes);
      return lastGeneratedSalt.getBytes("UTF-8");
    } catch (UnsupportedEncodingException e) {
      return null;
    }
  }

  /* (non-Javadoc)
   * @see org.jasypt.salt.SaltGenerator#includePlainSaltInEncryptionResults()
   */
  @Override
  public boolean includePlainSaltInEncryptionResults() {
    return false;
  }

  /*
   * (non-Javadoc)
   * 
   * @see me.sniggle.security.salt.SaltProvider#getLastGeneratedSalt()
   */
  @Override
  public String getLastGeneratedSalt() {
    return lastGeneratedSalt;
  }

  /* (non-Javadoc)
   * @see me.sniggle.security.salt.SaltProvider#getSaltString()
   */
  @Override
  public String getSaltString() {
    lastGeneratedSalt = createSalt(minSaltLength, maxSaltLength);
    return getLastGeneratedSalt();
  }

}
