package me.sniggle.security.digest;

/**
 * a common interface to hash and verify passwords securely and interchangeable
 * 
 * @author iulius
 * @since 0.0.1
 * 
 */
public interface HashGenerator {

  /**
   * defines the hash code type id, e.g. 5 for SHA-256 or 6 for SHA-512
   * 
   * @return
   */
  public abstract String getHashTypeCode();

  /**
   * hashes the plain text using a random salt and random number of rounds
   * 
   * @param plainText
   *          the plain text
   * @return the hashed value
   */
  public abstract String hashPassword(String plainText);

  /**
   * hashes the plain text using a defined salt and a defined number of rounds
   * 
   * @param plainText
   *          the plain text to hash
   * @param salt
   *          the salt to be used for the hash
   * @param rounds
   *          the number rounds to be applied
   * @return the hashed value
   */
  public abstract String hashPassword(String plainText, String salt, int rounds);

  /**
   * verifies whether the plain text results in the given hash
   * 
   * @param plainText
   *          the plain text to verify
   * @param formattedHash
   *          the formatted hash value to verify against, e.g.
   *          $5$rounds=5694$mJcb5xWijVC7ZQK4$Pt40CUyzJmBZKxmPUfWHNgsUJ
   *          /mO05nCfjMkOi0je/k=
   * @return true if the plain text matches the hash, else false
   */
  public abstract boolean verifyHash(String plainText, String formattedHash);

}