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
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;

import me.sniggle.security.crypto.Encryptor;
import me.sniggle.security.crypto.config.Algorithm;
import me.sniggle.security.crypto.stream.CipherOutputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author iulius
 *
 */
public abstract class BaseEncryptor extends BaseCryptor<PublicKey> implements Encryptor {

  private static final Logger LOGGER = LoggerFactory.getLogger(BaseEncryptor.class);

  protected BaseEncryptor(Algorithm algorithm, String provider) {
    super(algorithm, provider);
  }

  /**
   * the central and most generic method to encrypt the input data using a
   * public key
   * 
   * @param publicKey
   *          the public key used in the encryption
   * @param plainStream
   *          the plain input data stream
   * @param encryptedStream
   *          the encrypted output data stream
   * @return true if the encryption process was successful
   */
  protected boolean encrypt(PublicKey publicKey, InputStream plainStream, OutputStream encryptedStream) {
    boolean result = checkEncryptionInputData(publicKey, plainStream, encryptedStream) && initialize();
    if (result) {
      try {
        KeyFactory factory = getKeyFactory();
        RSAPublicKeySpec publicKeySpec = factory.getKeySpec(publicKey, RSAPublicKeySpec.class);
        int blockSize = (publicKeySpec.getModulus().bitLength() / 8);
        LOGGER.debug("Encryption block size {} bytes", blockSize);
        Cipher cipher = Cipher.getInstance(getAlgorithm().name());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        CipherOutputStream cos = null;
        try {
          cos = new CipherOutputStream(encryptedStream, cipher, blockSize);
          byte[] buffer = new byte[8192];
          int length;
          while ((length = plainStream.read(buffer)) != -1) {
            cos.write(buffer, 0, length);
          }
          cos.flush();
        } catch (IOException e) {
          LOGGER.error("Error during writing to encryption stream. {}", e.getMessage());
          result &= false;
        } finally {
          if (cos != null) {
            try {
              cos.close();
            } catch (IOException e) {
              result &= false;
              LOGGER.error("Error during writing to encryption stream. {}", e.getMessage());
            }
          }
        }
      } catch (GeneralSecurityException e) {
        LOGGER.error("Error during specifying key details. {}", e.getMessage());
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
    return new RSAPublicKeySpec(modulus, exponent);
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
    return factory.generatePublic(keySpec);
  }

  /*
   * (non-Javadoc)
   * 
   * @see me.sniggle.security.crypto.Encryptor#encrypt(java.io.InputStream,
   * java.io.OutputStream)
   */
  @Override
  public boolean encrypt(InputStream plainStream, OutputStream encryptedStream) {
    return encrypt(getKey(), plainStream, encryptedStream);
  }

  /*
   * (non-Javadoc)
   * 
   * @see me.sniggle.security.crypto.Encryptor#encrypt(java.io.InputStream,
   * java.io.InputStream, java.io.OutputStream)
   */
  @Override
  public boolean encrypt(InputStream publicKey, InputStream plainStream, OutputStream encryptedStream) {
    boolean result = loadKey(publicKey);
    if (result) {
      result &= encrypt(getKey(), plainStream, encryptedStream);
    }
    return result;
  }

}
