/**
 * 
 */
package me.sniggle.security.digest.impl;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import me.sniggle.security.crypto.config.RoundConfiguration;
import me.sniggle.security.digest.HashGenerator;
import me.sniggle.security.digest.config.Algorithm;
import me.sniggle.security.salt.impl.RandomSaltProvider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The base class for generating hashes, assembling hash algorithm independent
 * methods
 * 
 * @author iulius
 * @since 0.0.1
 * 
 */
public abstract class BaseHashGenerator implements HashGenerator {

  private static final Logger LOGGER = LoggerFactory.getLogger(BaseHashGenerator.class);

  private final RoundConfiguration roundConfiguration;

  private final Algorithm algorithm;

  /**
   * the default constructor uses a range of iterations form 5000 to 9000 to
   * hash the text
   */
  protected BaseHashGenerator(Algorithm algorithm) {
    this(algorithm, new RoundConfiguration(5000, 9000));
  }

  /**
   * @param roundConfiguration
   *          the custom declaration of iterations in order to cater your
   *          specific needs
   */
  protected BaseHashGenerator(Algorithm algorithm, RoundConfiguration roundConfiguration) {
    super();
    this.algorithm = algorithm;
    this.roundConfiguration = roundConfiguration;
  }

  /**
   * 
   * @return the message digester instance
   */
  protected MessageDigest getMessageDigest() {
    try {
      return MessageDigest.getInstance(getAlgorithm().alternateName());
    } catch (NoSuchAlgorithmException e) {
      return null;
    }
  }

  /**
   * 
   * @return the algorithm used for this implementation
   */
  public Algorithm getAlgorithm() {
    return algorithm;
  }

  /**
   * 
   * @return the magic prefix without the leading and trailing dollar sign
   */
  @Override
  public String getHashTypeCode() {
    String result = getMagicPrefix();
    return (result != null && result.length() >= 3) ? result.substring(1, 3) : null;
  }

  /**
   * 
   * @return the configuration of minimal and maximal rounds
   */
  protected RoundConfiguration getRoundConfiguration() {
    return roundConfiguration;
  }

  /**
   * 
   * @return the minimum number rounds
   */
  protected int getMinimumRounds() {
    return getRoundConfiguration() != null ? getRoundConfiguration().getMinimumRounds() : 1000;
  }

  /**
   * 
   * @return the maximum number of rounds
   */
  protected int getMaximumRounds() {
    return getRoundConfiguration() != null ? getRoundConfiguration().getMaximumRounds() : 999999999;
  }

  /**
   * 
   * @return a (pseudo-)randomly generated number of rounds to be used. the
   *         value is between the minimum and maximum number of rounds as
   *         defined in {@link #getRoundConfiguration()}
   */
  protected int getRandomRounds() {
    SecureRandom random = new SecureRandom();
    return getMinimumRounds() + random.nextInt(getMaximumRounds() - getMinimumRounds());
  }

  /**
   * 
   * @return the magic prefix for the hash value, e.g. $5$ for SHA-256
   */
  protected String getMagicPrefix() {
    return algorithm.magicPrefix();
  }

  /**
   * provides the default round count as specified in the specification
   * 
   * @return 1
   */
  protected int getDefaultRoundCount() {
    return 1;
  }

  /**
   * the minimum salt length
   * 
   * @return 8
   */
  protected int getMinimumSaltLength() {
    return 8;
  }

  /**
   * the maximum salt length as mentioned in the specification
   * 
   * @return 16
   */
  protected int getSaltLength() {
    return 16;
  }

  /**
   * 
   * @param requestedRounds
   *          the number of rounds to be used
   * @return if requestedRounds <= 0 then {@link #getDefaultRoundCount()}, <br>
   *         if requestedRounds < {@link #getMinimumRounds()} then
   *         {@link #getMinimumRounds()}, <br>
   *         if requestedRounds > {@link #getMaximumRounds()} then
   *         {@link #getMaximumRounds()},<br>
   *         else requestedRounds
   */
  protected int verifyRounds(int requestedRounds) {
    if (requestedRounds <= 0) {
      LOGGER.info("requested rounds equals Integer.MIN_VALUE setting to default rounds");
      return getDefaultRoundCount();
    } else if (requestedRounds < getMinimumRounds()) {
      LOGGER.info("requested rounds were less than minimun, setting to minimum");
      return getMinimumRounds();
    }
    if (requestedRounds > getMaximumRounds()) {
      LOGGER.info("requested rounds were more than allowed, setting to maximum allowed rounds");
      return getMaximumRounds();
    }
    return requestedRounds;
  }

  /**
   * verifies whether the given salt meets the length criteria. if the minimum
   * length is not met an entirely new salt will be generated, if the maximum
   * length is exceeded the salt will be truncated
   * 
   * @param testSalt
   *          the salt to verify
   * @return if testSalt == null then {@link #createSalt()}, <br>
   *         if testSalt > {@link #getSaltLength()} then testSalt.substring(0,
   *         {@link #getSaltLength()}), <br>
   *         else testSalt
   */
  protected String verifySalt(String testSalt) {
    if (testSalt != null) {
      return (testSalt.length() <= getSaltLength()) ? testSalt : testSalt.substring(0, getSaltLength());
    }
    return new RandomSaltProvider(getMinimumSaltLength(), getSaltLength()).getSaltString();
  }

}
