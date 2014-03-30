/**
 * 
 */
package me.sniggle.security.crypto.impl;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import me.sniggle.security.crypto.config.Algorithm;
import me.sniggle.security.crypto.config.SecurityLevel;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * a simple class to generate private/public key pair for asymmetric encryption
 * 
 * @author iulius
 * @since 0.0.1
 * 
 */
public abstract class AsymetricKeyGenerator {

  private static final Logger LOGGER = LoggerFactory.getLogger(AsymetricKeyGenerator.class);

  private final Object lock = new Object();

  private KeyPairGenerator keyPairGenerator;

  private KeyFactory keyFactory;

  private boolean initialized = false;

  private SecurityLevel securityLevel = SecurityLevel.MEDIUM;

  private final String provider;

  /**
   * constructor
   * 
   * @param securityLevel
   *          the {@link SecurityLevel} to be used, may not be null
   * @param provider
   *          the security provider to be used, supports "BC" or "SC"
   */
  protected AsymetricKeyGenerator(SecurityLevel securityLevel, String provider) {
    super();
    if (securityLevel == null) {
      throw new IllegalArgumentException("The security level may not be null!");
    }
    this.securityLevel = securityLevel;
    this.provider = provider;
  }

  /**
   * 
   * @param initialized
   */
  public void setInitialized(boolean initialized) {
    this.initialized = initialized;
  }

  /**
   * convenience method to check whether the targets are not null
   * 
   * @param privateTarget
   *          the target of the private key
   * @param publicTarget
   *          the target of the public key
   * @return true if both targets are not null
   */
  private <T> boolean checkKeyTargets(T privateTarget, T publicTarget) {
    boolean result = true;
    if (privateTarget == null) {
      LOGGER.error("The target of the private key may not be null");
      result &= false;
    }
    if (publicTarget == null) {
      LOGGER.error("The target of the public key may not be null");
      result &= false;
    }
    return result;
  }

  /**
   * 
   * @return
   */
  public boolean isInitialized() {
    return initialized;
  }

  /**
   * 
   * @return
   */
  protected abstract boolean initializeSecurityProvider();

  /**
   * initializes the key pair generation infrastructure
   * 
   * @return true if initialization was successful
   */
  private boolean initialize() {
    if (!isInitialized()) {
      synchronized (lock) {
        try {
          if (Security.getProvider(provider) == null) {
            LOGGER.debug("Adding spongycastle JCE security provider");
            initialized = initializeSecurityProvider();
          }
          keyPairGenerator = KeyPairGenerator.getInstance(Algorithm.RSA.name(), provider);
          keyPairGenerator.initialize(securityLevel.keyLength());
          keyFactory = KeyFactory.getInstance(Algorithm.RSA.name(), provider);
        } catch (GeneralSecurityException e) {
          LOGGER.error("Error initializing security infrastructure. {}", e.getMessage());
          initialized = false;
        }
      }
    }
    return isInitialized();
  }

  /**
   * helper method to centralize output of keys
   * 
   * @param out
   *          the output stream
   * @param mod
   *          the modulus of the key
   * @param exp
   *          the exponent of the key
   * @return true if data was written to out successfully
   */
  private boolean writeToStream(OutputStream out, BigInteger mod, BigInteger exp) {
    boolean result = true;
    String message = "Error writing security key. {}";
    ObjectOutputStream oos = null;
    try {
      oos = new ObjectOutputStream(out);
      oos.writeObject(mod);
      oos.writeObject(exp);
      oos.flush();
    } catch (IOException e) {
      LOGGER.error(message, e.getMessage());
      result &= false;
    } finally {
      if (oos != null) {
        try {
          oos.close();
        } catch (IOException e) {
          LOGGER.error(message, e.getMessage());
        }
      }
    }
    return result;
  }

  /**
   * simple method to generate a key pair at the provided location of the file
   * system
   * 
   * @param privateKey
   *          the location where the private key will be stored (maybe created
   *          if it doesn't exist), may not be null
   * @param publicKey
   *          the location where the public key will be stored (maybe created if
   *          it doesn't exist), may not be null
   * @return true when the key pair was created successfully
   * @throws IOException
   *           indicates error during write
   */
  public boolean generateKeyPair(File privateKey, File publicKey) throws IOException {
    boolean result = checkKeyTargets(privateKey, publicKey);
    if (result) {
      FileOutputStream privateKeyStream = null;
      try {
        privateKeyStream = new FileOutputStream(privateKey);
        FileOutputStream publicKeyStream = null;
        try {
          publicKeyStream = new FileOutputStream(publicKey);
          result &= generateKeyPair(privateKeyStream, publicKeyStream);
        } finally {
          if (publicKeyStream != null) {
            publicKeyStream.close();
          }
        }
      } finally {
        if (privateKeyStream != null) {
          privateKeyStream.close();
        }
      }
    }
    return result;
  }

  /**
   * convenience method used to save the key pair to the provided paths
   * 
   * @param privateKey
   *          the destination path incl. the filename of the private key
   * @param publicKey
   *          the destination path incl. the filename of the public key
   * @return true when the key pair was created successfully
   * @throws IOException
   *           indicates error during write
   */
  public boolean generateKeyPair(String privateKey, String publicKey) throws IOException {
    boolean result = checkKeyTargets(privateKey, publicKey);
    if (result) {
      result &= generateKeyPair(new File(privateKey), new File(publicKey));
    }
    return result;
  }

  /**
   * generic generation method writing the key pair to arbitrary streams
   * 
   * @param privateKey
   *          target stream of the private key
   * @param publicKey
   *          target stream of the public key
   * @return true if generation process was successfully completed
   */
  public boolean generateKeyPair(OutputStream privateKey, OutputStream publicKey) {
    boolean result = checkKeyTargets(privateKey, publicKey) && initialize();
    if (result) {
      synchronized (lock) {
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        try {
          RSAPrivateKeySpec privateKeySpecification = keyFactory.getKeySpec(keyPair.getPrivate(), RSAPrivateKeySpec.class);
          RSAPublicKeySpec publicKeySpecification = keyFactory.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class);
          result &= writeToStream(privateKey, privateKeySpecification.getModulus(), privateKeySpecification.getPrivateExponent());
          if (result) {
            result &= writeToStream(publicKey, publicKeySpecification.getModulus(), publicKeySpecification.getPublicExponent());
          }
        } catch (InvalidKeySpecException e) {
          LOGGER.error("Error during generation of key generation. {}", e.getMessage());
          result &= false;
        }
      }
    }
    return result;
  }

}
