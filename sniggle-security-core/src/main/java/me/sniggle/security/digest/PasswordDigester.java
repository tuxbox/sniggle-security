package me.sniggle.security.digest;

import me.sniggle.security.digest.config.PasswordMatchResult;

/**
 * The basic interface to create a password digester
 * 
 * @author iulius
 * @since 0.0.1
 * 
 */
public interface PasswordDigester {

  /**
   * hashes the given plain text with the algorithm used by the implementing
   * class
   * 
   * @param plainText
   *          the plain text to be hashed
   * @return the hash value
   */
  public abstract String hashPassword(String plainText);

  /**
   * verifies whether the provided plain text matches the formatted hash
   * 
   * @param plainText
   *          the plain text to be verified
   * @param formattedHash
   *          the formatted hash to be used for verification
   * @return a {@link PasswordMatchResult} instance
   */
  public abstract PasswordMatchResult matchesPassword(String plainText, String formattedHash);

}