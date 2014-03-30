package me.sniggle.security.crypto;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * Common interface to simplify the provision of various encryption classes
 * 
 * @author iulius
 * @since 0.0.1
 * 
 */
public interface Encryptor {

  /**
   * encrypts the plain data stream using a previously defined public key
   * 
   * @param plainStream
   *          the plain data stream
   * @param encryptedStream
   *          the encrypted data stream
   * @return true if everything worked
   */
  public abstract boolean encrypt(InputStream plainStream, OutputStream encryptedStream);

  /**
   * encrypts the plain data stream using the provided public key data
   * 
   * @param publicKey
   *          the public key data stream
   * @param plainStream
   *          the plain data stream
   * @param encryptedStream
   *          the encrypted data stream
   * @return true if everything worked well
   */
  public abstract boolean encrypt(InputStream publicKey, InputStream plainStream, OutputStream encryptedStream);

}