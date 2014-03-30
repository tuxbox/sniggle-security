/**
 * 
 */
package me.sniggle.security.crypto.config;

/**
 * Simple class specifying the range of iterations used for hashing a plain text
 * 
 * @author iulius
 * @since 0.0.1
 * 
 */
public class RoundConfiguration {

  private int minimumRounds;
  private int maximumRounds;

  /**
   * 
   */
  public RoundConfiguration() {
    super();
  }

  /**
   * @param minimumRounds
   * @param maximumRounds
   */
  public RoundConfiguration(int minimumRounds, int maximumRounds) {
    super();
    this.minimumRounds = minimumRounds;
    this.maximumRounds = maximumRounds;
  }

  /**
   * @return the minimumRounds
   */
  public int getMinimumRounds() {
    return minimumRounds;
  }

  /**
   * @return the maximumRounds
   */
  public int getMaximumRounds() {
    return maximumRounds;
  }

}
