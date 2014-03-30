/**
 * 
 */
package me.sniggle.security.crypto.impl;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.Security;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;

import me.sniggle.security.crypto.config.Algorithm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class assembles commonly used methods for the {@link BcAsymetricEncryptor}
 * and {@link BcAsymetricDecryptor} class
 * 
 * @author iulius
 * @since 0.0.1
 * 
 */
public abstract class BaseCryptor<T extends Key> {

  private static final List<String> SUPPORTED_PROVIDERS = Arrays.asList("BC", "SC");

  private static final Object LOCK = new Object();
  private static final Logger LOGGER = LoggerFactory.getLogger(BaseCryptor.class);

  private boolean initialized = false;
  private T key;
  private final Algorithm algorithm;
  private KeyFactory keyFactory;
  private final String provider;

  /**
   * constructor
   * 
   * @param algorithm
   *          the supported algorithm to be used as specified in
   *          {@link Algorithm}, may not be null
   * @param provider
   *          the provider to be used, valid values are "SC" and "BC"
   */
  protected BaseCryptor(Algorithm algorithm, String provider) {
    super();
    if (algorithm == null) {
      throw new IllegalArgumentException("The specified algorithm may not be null!");
    }
    if( provider == null || !SUPPORTED_PROVIDERS.contains(provider) ) {
      throw new IllegalArgumentException("Invalid security provider specified (" + provider + ")");
    }
    this.algorithm = algorithm;
    this.provider = provider;
  }

  /**
   * creates an appropriate key specification for the given modulus and exponent
   * 
   * @param modulus
   *          the modulus of the key
   * @param exponent
   *          the exponent of the key
   * @return the key specification
   */
  protected abstract KeySpec createKeySpec(BigInteger modulus, BigInteger exponent);

  /**
   * identifies wheter the crypto class has been initialized
   * 
   * @return true if initialized
   */
  protected boolean isInitialized() {
    return initialized;
  }

  /**
   * initializes the crypto class trying to add the spongycastle crypto provider <br>
   * <br>
   * this method is being synchronized in order to avoid multiple instantiation
   * of the spongycaste crypto provider
   * 
   * @return true if initialization is successful
   */
  protected boolean initialize() {
    synchronized (LOCK) {
      if (!isInitialized()) {
        try {
          if (Security.getProvider(provider) == null) {
            LOGGER.debug("Adding spongycastle JCS provider");
            addSecurityProvider();
          }
          keyFactory = KeyFactory.getInstance(getAlgorithm().name(), provider);
          initialized = true;
        } catch (GeneralSecurityException e) {
          LOGGER.error("Error during initialization of security infrastructure. {}", e.getMessage());
          initialized &= false;
        }
      }
    }
    return isInitialized();
  }

  protected abstract void addSecurityProvider();

  protected String getProvider() {
    return provider;
  }

  /**
   * convenience method used to check whether all input data needed for the
   * encryption is being provided appropriately
   * 
   * @param key
   *          the key
   * @param inputData
   *          the source data stream
   * @param outputData
   *          the output data stream
   * @return returns false if any argument is null
   */
  protected boolean checkEncryptionInputData(Key key, InputStream inputData, OutputStream outputData) {
    boolean result = true;
    if (key == null) {
      LOGGER.error("The provided key for the operation may not be null!");
      result &= false;
    }
    if (inputData == null) {
      LOGGER.error("No valid input data provided. The data may not be null!");
      result &= false;
    }
    if (outputData == null) {
      LOGGER.error("No valid output data target provided. The output data target may not be null!");
      result &= false;
    }
    return result;
  }

  /**
   * convenience method which provides the appropriate Cipher instance for the
   * defined provider
   * 
   * @return
   * @throws GeneralSecurityException
   */
  protected Cipher getCipherInstance() throws GeneralSecurityException {
    return Cipher.getInstance(algorithm.name(), provider);
  }

  /**
   * 
   * @return the key instance
   */
  protected T getKey() {
    return key;
  }

  /**
   * 
   * @return the currently used algorithm
   */
  protected Algorithm getAlgorithm() {
    return algorithm;
  }

  /**
   * 
   * @return the factory used to create the keys
   */
  protected KeyFactory getKeyFactory() {
    initialize();
    return keyFactory;
  }

  /**
   * loads the key file used for de-/encryption
   * 
   * @param filename
   *          the path and filename of the key to be loaded
   * @return true if load was successful
   */
  public boolean loadKey(String filename) {
    return loadKey(new File(filename));
  }

  /**
   * loads the key file used for de-/encryption
   * 
   * @param file
   *          the key file to be loaded
   * @return true if load was successful
   */
  public boolean loadKey(File file) {
    String message = "Error loading security key. {}";
    if (file != null && file.exists()) {
      FileInputStream fis = null;
      try {
        fis = new FileInputStream(file);
        return loadKey(fis);
      } catch (IOException e) {
        LOGGER.error(message, e.getMessage());
      } finally {
        if (fis != null) {
          try {
            fis.close();
          } catch (IOException e) {
            LOGGER.error(message, e.getMessage());
          }
        }
      }
    }
    return false;
  }

  /**
   * reads the key data used for de-/encryption
   * 
   * @param in
   *          the input stream providing the key
   * @return true if key was being loaded successfully
   */
  // The cast is safe
  @SuppressWarnings("unchecked")
  public boolean loadKey(InputStream in) {
    boolean result = true;
    initialize();
    String message = "Error reading security key. {}";
    ObjectInputStream ois = null;
    try {
      ois = new ObjectInputStream(in);
      BigInteger modulus = (BigInteger) ois.readObject();
      BigInteger exponent = (BigInteger) ois.readObject();
      KeySpec keySpec = createKeySpec(modulus, exponent);
      Key localKey = generateKey(keySpec);
      key = (T) localKey;
    } catch (ClassNotFoundException e) {
      LOGGER.error(message, e.getMessage());
      result &= false;
    } catch( IOException e) {
      LOGGER.error(message, e.getMessage());
      result &= false;
    } catch(GeneralSecurityException e){
      LOGGER.error(message, e.getMessage());
      result &= false;
    } finally {
      if( ois != null ) {
        try {
          ois.close();
        } catch (IOException e) {
          result &= false;
          LOGGER.error(message, e.getMessage());
        }
      }
    }
    return result;
  }

  /**
   * generates the appropriate key using the provided specification
   * 
   * @param keySpec
   *          the key specification
   * @return the appropriate key object
   * @throws GeneralSecurityException
   */
  protected abstract Key generateKey(KeySpec keySpec) throws GeneralSecurityException;

}
