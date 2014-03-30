package me.sniggle.security.digest.impl;

import java.security.MessageDigest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import me.sniggle.security.crypto.config.RoundConfiguration;
import me.sniggle.security.digest.config.Algorithm;
import me.sniggle.security.salt.SaltProvider;
import me.sniggle.security.salt.impl.FixedSaltProvider;
import me.sniggle.security.salt.impl.RandomSaltProvider;

import org.jasypt.digest.StandardStringDigester;

/**
 * This class assembles all the methods to create a standard JASYPT library
 * based hash and can be used for all hash algorithms provided by jasypt
 * 
 * @author iulius
 * @since 0.0.1
 * 
 */
public class JasyptHashGenerator extends BaseHashGenerator {

  private static final Pattern HASH_PATTERN = Pattern.compile("\\$([0-9]+)\\$([0-9]+)\\$(.+)\\$(.+)");

  public JasyptHashGenerator(Algorithm algorithm) {
    super(algorithm);
  }

  public JasyptHashGenerator(Algorithm algorithm, RoundConfiguration configuration) {
    super(algorithm, configuration);
  }

  /**
   * this returns null as we are relying on the JASYPT implementation
   */
  @Override
  protected MessageDigest getMessageDigest() {
    return null;
  }

  /**
   * create a salt provider, either a RandomSaltProvider, or FixedSaltProvider
   * in case a salt was provided
   * 
   * @param salt
   *          the salt to be used or null in order trigger the creation of a
   *          RandomSaltProvider
   * @return the appropriate SaltProvider
   */
  protected SaltProvider getSaltGenerator(String salt) {
    SaltProvider result;
    if (salt == null) {
      result = new RandomSaltProvider(getMinimumSaltLength(), getSaltLength());
    } else {
      result = new FixedSaltProvider(salt);
    }
    return result;
  }

  /*
   * (non-Javadoc)
   * 
   * @see
   * me.sniggle.security.digest.HashGenerator#hashPassword(java.lang.String)
   */
  @Override
  public String hashPassword(String plainText) {
    return hashPassword(plainText, null, getRandomRounds());
  }

  /*
   * (non-Javadoc)
   * 
   * @see
   * me.sniggle.security.crypto.HashGenerator#hashPassword(java.lang.String,
   * java.lang.String, int)
   */
  @Override
  public String hashPassword(String plainText, String salt, int rounds) {
    if (plainText != null) {
      StandardStringDigester digester = new StandardStringDigester();
      digester.setAlgorithm(getAlgorithm().alternateName());
      int iterations = verifyRounds(rounds);
      digester.setIterations(iterations);
      SaltProvider provider = getSaltGenerator(verifySalt(salt));
      digester.setSaltGenerator(provider);
      String hashValue = digester.digest(plainText);
      return getMagicPrefix() + iterations + "$" + provider.getLastGeneratedSalt() + "$" + hashValue;
    }
    return null;
  }

  /*
   * (non-Javadoc)
   * 
   * @see me.sniggle.security.crypto.HashGenerator#verifyHash(java.lang.String,
   * java.lang.String)
   */
  @Override
  public boolean verifyHash(String plainText, String formattedHash) {
    if (plainText != null && formattedHash != null) {
      Matcher matcher = HASH_PATTERN.matcher(formattedHash);
      if (matcher.matches()) {
        String hashedPlainText = hashPassword(plainText, matcher.group(3), Integer.valueOf(matcher.group(2)));
        return formattedHash.equals(hashedPlainText);
      }
    }
    return false;
  }

}
