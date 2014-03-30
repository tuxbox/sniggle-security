/**
 * 
 */
package me.sniggle.security.digest.impl;

import java.lang.reflect.Constructor;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import me.sniggle.security.digest.HashGenerator;
import me.sniggle.security.digest.PasswordDigester;
import me.sniggle.security.digest.config.Algorithm;
import me.sniggle.security.digest.config.PasswordMatchResult;
import me.sniggle.security.exception.ReflectiveOperationException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class handles the hashing of all algorithms specified in
 * {@link Algorithm}
 * 
 * @author iulius
 * @since 0.0.1
 * 
 */
public class SecurePasswordDigester implements PasswordDigester {

  private static final Logger LOGGER = LoggerFactory.getLogger(SecurePasswordDigester.class);

  private static final Pattern FORMATTED_DIGEST_PATTERN = Pattern.compile("^(\\$[0-9]+\\$)(rounds=)?([0-9]+)\\$(.+)\\$(.+)");
  
  /**
   * default constructor
   */
	public SecurePasswordDigester() {
    super();
	}

  /**
   * creates the hash generator for the given algorithm using the applicable
   * rules
   * 
   * @param algorithm
   *          the algorithm to be used
   * @return the hash generator
   * @throws ReflectiveOperationException
   *           thrown if now matching constructor is being found
   */
  private static HashGenerator createHashGenerator(Algorithm algorithm) throws ReflectiveOperationException {
    try {
      LOGGER.debug("Trying to instantiate hash generator with default constructor");
      Constructor<?> constructor = algorithm.hashGeneratorClass().getConstructor();
      return (HashGenerator) constructor.newInstance();
    } catch (NoSuchMethodException e) {
      LOGGER.debug("No default constructor found, trying Algorithm-constructor");
      Constructor<?> constructor;
      try {
        constructor = algorithm.hashGeneratorClass().getConstructor(Algorithm.class);
        return (HashGenerator) constructor.newInstance(algorithm);
      } catch (Exception e1) {
        throw new ReflectiveOperationException(e1);
      }
    } catch (Exception e) {
      throw new ReflectiveOperationException(e);
    }
  }

  /**
   * creates a hash generator based on the provided algorithm and hashes the
   * provided plain text accordingly
   * 
   * @param plainText
   *          the plain text to be hashed
   * @param algorithm
   *          the algorithm to be used
   * @return the hash value or null in case of an error
   */
  protected String hashPassword(String plainText, Algorithm algorithm) {
    try {
      HashGenerator hashGenerator = createHashGenerator(algorithm);
      return hashGenerator.hashPassword(plainText);
    } catch (SecurityException e) {
      LOGGER.error("Error during hashing! {}", e.getMessage());
    } catch (ReflectiveOperationException e) {
      LOGGER.error("Error during hashing! {}", e.getMessage());
    }
    return null;
  }

  /* (non-Javadoc)
   * @see me.sniggle.security.commons.PasswordHasher#hashPassword(java.lang.String)
   */
  @Override
  public String hashPassword(String plainText) {
    return hashPassword(plainText, Algorithm.getBest());
  }

  /* (non-Javadoc)
   * @see me.sniggle.security.commons.PasswordHasher#matchesPassword(java.lang.String, java.lang.String)
   */
  @Override
  public PasswordMatchResult matchesPassword(String plainText, String formattedHash) {
    Matcher matcher = FORMATTED_DIGEST_PATTERN.matcher(formattedHash);
    PasswordMatchResult result = null;
    if (matcher.matches()) {
      LOGGER.debug("Determine magic prefix");
      String magicPrefix = matcher.group(1);
      LOGGER.debug("Determine suitable algorithm");
      Algorithm algorithm = Algorithm.getForMagicPrefix(magicPrefix);
      try {
        HashGenerator hashGenerator = createHashGenerator(algorithm);
        result = new PasswordMatchResult(false, null);
        LOGGER.debug("verifying plaintext value");
        if (hashGenerator.verifyHash(plainText, formattedHash)) {
          LOGGER.debug("plain text is verified");
          result.setMatching(true);
          Algorithm bestAlgorithm = Algorithm.getBest();
          if (algorithm != bestAlgorithm) {
            LOGGER.info("The used hash value is outdated and a new hash is being created for the plain text!");
            result.setUpdatedHash(hashPassword(plainText));
          }
        }
      } catch (SecurityException e) {
        LOGGER.error("Error during verification of plain text! {}", e.getMessage());
      } catch (ReflectiveOperationException e) {
        LOGGER.error("Error during hashing! {}", e.getMessage());
      }
    } else {
      LOGGER.warn("The provided hash ({}) does not match the implemented pattern!", formattedHash);
    }
    return result;
  }

}
