/**
 * 
 */
package me.sniggle.security.salt;

import org.jasypt.salt.SaltGenerator;

/**
 * extends the {@link SaltGenerator} interface in order to allow the retrieval
 * of the used Salt string
 * 
 * @author iulius
 * 
 */
public interface SaltProvider extends SaltGenerator {

  /**
   * 
   * @return the salt string being used
   */
  public abstract String getSaltString();

  /**
   * 
   * @return the last generated salt
   */
  public abstract String getLastGeneratedSalt();

}
