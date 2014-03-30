/**
 * 
 */
package me.sniggle.security.crypto.impl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateKeySpec;

import javax.crypto.Cipher;

import me.sniggle.security.crypto.Decryptor;
import me.sniggle.security.crypto.config.Algorithm;
import me.sniggle.security.crypto.stream.CipherInputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author iulius
 *
 */
public abstract class BaseDecryptor extends BaseCryptor<PrivateKey> implements Decryptor {

  private static final Logger LOGGER = LoggerFactory.getLogger(BaseDecryptor.class);

  protected BaseDecryptor(Algorithm algorithm, String provider) {
    super(algorithm, provider);
  }

  /**
   * this is the central and most generic method to decrypt the encrypted input
   * data
   * 
   * @param privateKey
   *          the private key used for decryption
   * @param encryptedStream
   *          the encrypted input data as stream
   * @param plainStream
   *          the decrypted data as output stream
   * @return true if the decryption process finished successfully
   */
  protected boolean decrypt(PrivateKey privateKey, InputStream encryptedStream, OutputStream plainStream) {
    boolean result = checkEncryptionInputData(privateKey, encryptedStream, plainStream) && initialize();
    if (result) {
      try {
        RSAPrivateKeySpec keySpec = getKeyFactory().getKeySpec(privateKey, RSAPrivateKeySpec.class);
        int keySize = keySpec.getModulus().bitLength();
        LOGGER.debug("Private key length: {}", keySize);
        Cipher cipher = getCipherInstance();
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        CipherInputStream cis = null;
        try {
          cis = new CipherInputStream(encryptedStream, cipher, keySize / 8);
          byte[] buffer = new byte[8192];
          int length;
          while ((length = cis.read(buffer)) != -1) {
            plainStream.write(buffer, 0, length);
          }
          plainStream.flush();
        } catch (IOException e) {
          LOGGER.error("Error reading encrypted stream. {}", e.getMessage());
          result &= false;
        } finally {
          if (cis != null) {
            try {
              cis.close();
            } catch (IOException e) {
              result &= false;
              LOGGER.error("Error reading encrypted stream. {}", e.getMessage());
            }
          }
        }
      } catch (GeneralSecurityException e1) {
        LOGGER.error("Error during specifying key details. {}", e1.getMessage());
        result &= false;
      }
    }
    return result;
  }

  /*
   * (non-Javadoc)
   * 
   * @see
   * me.sniggle.security.crypto.BaseCryptor#createKeySpec(java.math.BigInteger,
   * java.math.BigInteger)
   */
  @Override
  protected KeySpec createKeySpec(BigInteger modulus, BigInteger exponent) {
    return new RSAPrivateKeySpec(modulus, exponent);
  }

  /*
   * (non-Javadoc)
   * 
   * @see
   * me.sniggle.security.crypto.BaseCryptor#generateKey(java.security.spec.KeySpec
   * )
   */
  @Override
  protected Key generateKey(KeySpec keySpec) throws GeneralSecurityException {
    KeyFactory factory = KeyFactory.getInstance(getAlgorithm().name());
    return factory.generatePrivate(keySpec);
  }

  /*
   * (non-Javadoc)
   * 
   * @see me.sniggle.security.crypto.Decryptor#decrypt(java.io.InputStream,
   * java.io.OutputStream)
   */
  @Override
  public boolean decrypt(InputStream encryptedStream, OutputStream plainStream) {
    return decrypt(getKey(), encryptedStream, plainStream);
  }

  /*
   * (non-Javadoc)
   * 
   * @see me.sniggle.security.crypto.Decryptor#decrypt(java.io.InputStream,
   * java.io.InputStream, java.io.OutputStream)
   */
  @Override
  public boolean decrypt(InputStream privateKey, InputStream encryptedStream, OutputStream plainStream) {
    boolean result = loadKey(privateKey);
    if (result) {
      result &= decrypt(getKey(), encryptedStream, plainStream);
    }
    return result;
  }

}
