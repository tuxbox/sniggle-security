package me.sniggle.security.digest.config;

import me.sniggle.security.digest.HashGenerator;
import me.sniggle.security.digest.impl.JasyptHashGenerator;
import me.sniggle.security.digest.impl.Sha256Crypt;
import me.sniggle.security.digest.impl.Sha512Crypt;

/**
 * This enumeration lists all implemented hashing algorithms and provides the
 * identifier, priority and the implementing class of the algorithm
 * 
 * @author iulius
 * @since 0.0.1
 */
public enum Algorithm {
  MD5(1, "$1$", JasyptHashGenerator.class),
  SHA256(2, "$3$", JasyptHashGenerator.class, "SHA-256"),
  SHA512(3, "$4$", JasyptHashGenerator.class, "SHA-512"),
  SHA256_CRYPT(4, "$5$", Sha256Crypt.class),
  SHA512_CRYPT(5, "$6$", Sha512Crypt.class);

  private int priority;
  private String magicPrefix;
  private Class<? extends HashGenerator> hashGeneratorClass;
  private String alternateName;

  /**
   * constructor
   * 
   * @param priority
   *          the priority to determine an algorithm's security
   * @param magicPrefix
   *          the magic prefix to identify the algorithm in a hash
   * @param hashGenerator
   *          the implementation class
   */
  private Algorithm(int priority, String magicPrefix, Class<? extends HashGenerator> hashGenerator) {
    this.priority = priority;
    this.magicPrefix = magicPrefix;
    this.hashGeneratorClass = hashGenerator;
    this.alternateName = name();
  }

  /**
   * constructor
   * 
   * @param priority
   *          the priority to determine an algorithm's security
   * @param magicPrefix
   *          the magic prefix to identify the algorithm in a hash
   * @param hashGenerator
   *          the implementation class
   * @param alternateName
   *          the name as used in the underlying implementation (e.g. the JASYPT
   *          name)
   */
  private Algorithm(int priority, String magicPrefix, Class<? extends HashGenerator> hashGenerator, String alternateName) {
    this(priority, magicPrefix, hashGenerator);
    this.alternateName = alternateName;
  }

  /**
   * the priority is used to determine the most secure algorithm, which in turn
   * is used to determine the best algorithm (for which an implementation
   * exists) in {@link #getBest()}
   * 
   * @return the priority of the algorithm (higher is better)
   */
  public int priority() {
    return priority;
  }

  /**
   * 
   * @return the magic prefix to identify the used hash algorithm in a hashed
   *         password
   */
  public String magicPrefix() {
    return magicPrefix;
  }

  /**
   * 
   * @return the class which implements the algorithm
   */
  public Class<? extends HashGenerator> hashGeneratorClass() {
    return hashGeneratorClass;
  }

  /**
   * 
   * @return the alternate name if specified, otherwise the result equals {
   *         {@link #name()}
   */
  public String alternateName() {
    return alternateName;
  }

  /**
   * returns the suitable algorithm for the given prefix
   * 
   * @param magicPrefix
   *          the prefix to be checked
   * @return the algorithm matching the prefix or null im none matches
   */
  public static Algorithm getForMagicPrefix(String magicPrefix) {
    Algorithm result = null;
    for (Algorithm algorithm : values()) {
      if (algorithm.magicPrefix().equals(magicPrefix)) {
        result = algorithm;
      }
    }
    return result;
  }

  /**
   * returns the algorithm that offers the highest grade of security (of the
   * implemented)
   * 
   * @return the algorithm with the highest {@link #priority()}
   */
  public static Algorithm getBest() {
    Algorithm result = null;
    for (Algorithm algorithm : values()) {
      if (result == null || result.priority() < algorithm.priority()) {
        result = algorithm;
      }
    }
    return result;
  }
}
