package me.sniggle.security.digest.config;

/**
 * This class simplifies the determination whether a hash matches the provided
 * plain text and if applicable offers access to a newly hashed password in
 * order to upgrade the used hash algorithm
 * 
 * @author iulius
 * @since 0.0.1
 * 
 */
public class PasswordMatchResult {
  private boolean matching;
  private String updatedHash;

  /**
   * @param matching
   * @param updatedHash
   */
  public PasswordMatchResult(boolean matching, String updatedHash) {
    super();
    this.matching = matching;
    this.updatedHash = updatedHash;
  }

  /**
   * @return the matching
   */
  public boolean isMatching() {
    return matching;
  }

  /**
   * @return the updatedHash or null if no update is necessary
   */
  public String getUpdatedHash() {
    return updatedHash;
  }

  /**
   * @param matching
   *          the matching to set
   */
  public void setMatching(boolean matching) {
    this.matching = matching;
  }

  /**
   * @param updatedHash
   *          the updatedHash to set
   */
  public void setUpdatedHash(String updatedHash) {
    this.updatedHash = updatedHash;
  }

}
