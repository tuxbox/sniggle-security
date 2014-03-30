package me.sniggle.security.crypto;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * simple interface to allow easy provision of various decryption classes
 * 
 * @author iulius
 * @since 0.0.1
 * 
 */
public interface Decryptor {

  /**
   * decrypts the encrypted stream using a previously defined key
   * 
   * @param encryptedStream
   *          the encrypted data stream
   * @param plainStream
   *          the decrypted data stream
   * @return true if everything worked fine
   */
  public abstract boolean decrypt(InputStream encryptedStream, OutputStream plainStream);

  /**
   * decrypts the encrypted stream using the provided private key
   * 
   * @param privateKey
   *          the key data stream
   * @param encryptedStream
   *          the encrypted data stream
   * @param plainStream
   *          the plain data stream
   * @return true if everything worked well
   */
  public abstract boolean decrypt(InputStream privateKey, InputStream encryptedStream, OutputStream plainStream);

}