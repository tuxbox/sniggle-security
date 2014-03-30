package me.sniggle.security.digest.impl;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import me.sniggle.security.crypto.config.RoundConfiguration;
import me.sniggle.security.digest.config.Algorithm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base class used to implement the algorithm to create Sha256-CRYPT and
 * Sha512-CRYPTE based crypto hashes
 * 
 * @author iulius
 * @since 0.0.1
 * 
 */
public abstract class ShaCrypt extends BaseHashGenerator {

  private static final Pattern HASH_PATTERN = Pattern
.compile("^\\$([0-9]+)\\$(rounds=([0-9]+)\\$)?(.+)\\$([a-zA-Z0-9\\./]+)$");

  private static final Logger LOGGER = LoggerFactory.getLogger(ShaCrypt.class);

  private static final char[] BASE_64_ENCODING_ARRAY = new char[] { '.', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',
      'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
      'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };

  /**
   * constructor
   * 
   * @param algorithm
   *          the algorithm to be used
   */
  protected ShaCrypt(Algorithm algorithm) {
    super(algorithm);
  }

  /**
   * 
   * @param algorithm
   *          the algorithm to be used
   * @param config
   *          the configuration how many rounds shall be used as minimum or
   *          maximum
   */
  protected ShaCrypt(Algorithm algorithm, RoundConfiguration config) {
    super(algorithm, config);
  }

  /**
   * 
   * @return the input buffer length based on the algorithm being utilized
   */
  protected abstract int getInputBufferLength();

  /**
   * 
   * @return the prefix used to identify the rounds
   */
  protected String getRoundPrefix() {
    return "rounds=";
  }


  /**
   * provides the default round count as specified in the specification
   * 
   * @return 5000
   */
  @Override
  protected int getDefaultRoundCount() {
    return 5000;
  }

  // START SHA-CRYPT algorithm methods
  /**
   * creates the digest named B in the specification text
   * 
   * @param plainTextBytes
   *          the plain text as UTF-8 encoded byte array
   * @param saltBytes
   *          the salt as UTF-8 encoded byte array
   * @return the digest as specified in step 4 of the specification
   */
  private byte[] createDigestB(byte[] plainTextBytes, byte[] saltBytes) {
    // step 4
    MessageDigest digester = getMessageDigest();
    if (digester != null) {
      digester.reset();
      digester.update(plainTextBytes);
      digester.update(saltBytes);
      digester.update(plainTextBytes);
      byte[] result = digester.digest();
      digester.reset();
      return result;
    }
    return null;
  }

  /**
   * creates the digest named A in the specification
   * 
   * @param digester
   *          the main digester
   * @param plainTextBytes
   *          the plain text as UTF-8 encoded byte array
   * @param saltBytes
   *          the salt as UTF-8 encoded byte array
   * @param digestB
   *          the digest B
   * @return the digest A
   */
  private byte[] createDigestA(MessageDigest digester, byte[] plainTextBytes, byte[] saltBytes, byte[] digestB) {
    int inputBufferLength = getInputBufferLength();
    // step 2
    digester.update(plainTextBytes);
    // step 3
    digester.update(saltBytes);
    // step 9
    for (int i = plainTextBytes.length / inputBufferLength; i > 0; i--) {
      digester.update(digestB);
    }
    // step 10
    int rest = plainTextBytes.length % inputBufferLength;
    digester.update(digestB, 0, rest);
    // step 11
    // what happens here?
    for (int counter = plainTextBytes.length; counter > 0; counter >>= 1) {
      if ((counter & 1) != 0) {
        digester.update(digestB);
      } else {
        digester.update(plainTextBytes);
      }
    }
    // step 12
    return digester.digest();
  }

  /**
   * creates the digest named DP in the specification
   * 
   * @param digester
   *          the main digester
   * @param plainTextBytes
   *          the plain text as UTF-8 encoded array
   * @return the digest DP
   */
  private byte[] createDigestDP(MessageDigest digester, byte[] plainTextBytes) {
    // step 13
    digester.reset();
    // step 14
    for (@SuppressWarnings("unused")
    byte b : plainTextBytes) {
      digester.update(plainTextBytes);
    }
    // step 15
    return digester.digest();
  }

  /**
   * creates the digest named P in the specification. Variation of a digest
   * based on the plain text
   * 
   * @param plainTextBytesLength
   *          the length of the plain text byte array, aka. the size of the text
   *          in bytes
   * @param digestDP
   *          the digest DP
   * @return the digest P
   */
  private byte[] createPBytes(int plainTextBytesLength, byte[] digestDP) {
    int inputBufferLength = getInputBufferLength();
    // Step 16 a)
    byte[] pBytes = new byte[plainTextBytesLength];
    for (int i = 0; i < (plainTextBytesLength / inputBufferLength); i++) {
      System.arraycopy(digestDP, 0, pBytes, i * inputBufferLength, inputBufferLength);
    }
    // step 16 b)
    System.arraycopy(digestDP, 0, pBytes, inputBufferLength * (plainTextBytesLength / inputBufferLength),
        plainTextBytesLength % inputBufferLength);
    return pBytes;
  }

  /**
   * creates the digest named DS in the specification
   * 
   * @param digester
   *          the main digester
   * @param saltBytes
   *          the salt as UTF-8 encoded byte array
   * @param firstByteOfDigestB
   *          the first byte of the digest B
   * @return the digest DS
   */
  private byte[] createDigestDS(MessageDigest digester, byte[] saltBytes, byte firstByteOfDigestB) {
    // step 17
    digester.reset();
    // step 18
    for (int i = 0; i < 16 + (firstByteOfDigestB & 0xFF); ++i) {
      digester.update(saltBytes);
    }
    // step 19
    return digester.digest();
  }

  /**
   * creates the s byte array. Variation of a digest based on the salt bytes
   * 
   * @param saltBytesLength
   *          the length of the salt byte array, aka. the size of the salt in
   *          bytes
   * @param digestDS
   *          the digest DS
   * @return the s byte array
   */
  private byte[] createSBytes(int saltBytesLength, byte[] digestDS) {
    int inputBufferLength = getInputBufferLength();
    // step 20
    byte[] sBytes = new byte[saltBytesLength];
    // step 20a)
    for (int i = 0; i < (saltBytesLength / inputBufferLength); i++) {
      System.arraycopy(digestDS, 0, sBytes, i * inputBufferLength, inputBufferLength);
    }
    // step 20b)
    System.arraycopy(digestDS, 0, sBytes, inputBufferLength * (saltBytesLength / inputBufferLength), saltBytesLength
        % inputBufferLength);
    return sBytes;
  }

  /**
   * create the final digest, intentionally slowing down the hashing process
   * 
   * @param digester
   *          the main digester
   * @param actualRounds
   *          the number rounds used to hash the password
   * @param plainTextBytesLength
   *          the size of the plain text byte array
   * @param saltBytesLength
   *          the size of the salt byte array
   * @param digesterResult
   *          the digest to be hashed
   * @param pBytes
   *          the digest variation based on the plain text
   * @param sBytes
   *          the digest based on the salt
   * @return the final hash
   */
  private byte[] performComputation(MessageDigest digester, int actualRounds, int plainTextBytesLength, int saltBytesLength,
      byte[] digesterResult, byte[] pBytes, byte[] sBytes) {
    int inputBufferLength = getInputBufferLength();
    byte[] result = digesterResult;
    // step 21 use digesterResult as base
    for (int i = 0; i < actualRounds; i++) {
      digester.reset();
      if ((i & 1) != 0) {
        digester.update(pBytes, 0, plainTextBytesLength);
      } else {
        digester.update(result, 0, inputBufferLength);
      }
      if (i % 3 != 0) {
        digester.update(sBytes, 0, saltBytesLength);
      }
      if (i % 7 != 0) {
        digester.update(pBytes, 0, plainTextBytesLength);
      }
      if ((i & 1) != 0) {
        digester.update(result, 0, inputBufferLength);
      } else {
        digester.update(pBytes, 0, plainTextBytesLength);
      }
      result = digester.digest();
    }
    return result;
  }

  /**
   * creates the formatted hash value
   * 
   * @param actualRounds
   *          the number of rounds used to create the hash
   * @param finalHash
   *          the final hash as byte array
   * @param actualSalt
   *          the salt used to create the hash
   * @return the formatted hash value
   */
  private String createResultString(int actualRounds, byte[] finalHash, String actualSalt) {
    // step 22
    StringBuffer result = new StringBuffer(getMagicPrefix());
    if (actualRounds != getDefaultRoundCount()) {
      result.append(getRoundPrefix());
      result.append(actualRounds);
      result.append('$');
    }
    result.append(actualSalt);
    result.append('$');
    appendBase64OfHash(result, finalHash);
    return result.toString();
  }

  protected abstract void appendBase64OfHash(StringBuffer result, byte[] finalHash);

  /**
   * performs base 64 encoding on 3 bytes or 24bits
   * 
   * @param B2
   *          the first byte
   * @param B1
   *          the second byte
   * @param B0
   *          the third byte
   * @param length
   *          the number of characters in the result string
   * @return the result string with the length passed in
   */
  protected static final String createBase64EncodedStringFrom3bytes(byte B2, byte B1, byte B0, int length) {
    int v = (((B2) & 0xFF) << 16) | (((B1) & 0xFF) << 8) | (B0 & 0xff);
    StringBuilder result = new StringBuilder();
    while (--length >= 0) {
      result.append(BASE_64_ENCODING_ARRAY[v & 0x3f]);
      v >>>= 6;
    }
    return result.toString();
  }

  // END SHA-CRYPT algorithm methods

  /*
   * (non-Javadoc)
   * 
   * @see me.sniggle.security.crypto.CryptoHasher#hashPassword(java.lang.String)
   */
  @Override
  public String hashPassword(String plainText) {
    return hashPassword(plainText, verifySalt(null), getRandomRounds());
  }

  /*
   * (non-Javadoc)
   * 
   * @see me.sniggle.security.crypto.CryptoHasher#hashPassword(java.lang.String,
   * java.lang.String, int)
   */
  @Override
  public String hashPassword(String plainText, String salt, int rounds) {
    if (plainText != null) {
      try {
        MessageDigest digester = getMessageDigest();
        if (digester != null) {
          digester.reset();
          MessageDigest alternateDigester = getMessageDigest();
          alternateDigester.reset();
          String actualSalt = verifySalt(salt);
          int actualRounds = verifyRounds(rounds);
          byte[] plainTextBytes = plainText.getBytes("UTF-8");
          byte[] saltBytes = actualSalt.getBytes("UTF-8");
          // steps 4-8
          byte[] digestB = createDigestB(plainTextBytes, saltBytes);
          byte[] digestA = createDigestA(digester, plainTextBytes, saltBytes, digestB);
          byte[] pBytes = createPBytes(plainTextBytes.length, createDigestDP(alternateDigester, plainTextBytes));
          byte[] sBytes = createSBytes(saltBytes.length, createDigestDS(alternateDigester, saltBytes, digestA[0]));

          //@formatter:off
          String result = createResultString(actualRounds,
              performComputation(digester, actualRounds, plainTextBytes.length, saltBytes.length, digestA, pBytes, sBytes),
              actualSalt);
          //@formatter:on
          digester.reset();
          return result;
        }
      } catch (UnsupportedEncodingException e) {
        LOGGER.error(e.getMessage());
      }
    } else {
      LOGGER.info("No text to hash provided!");
    }
    return null;
  }

  /* (non-Javadoc)
   * @see me.sniggle.security.crypto.CryptoHasher#verifyHash(java.lang.String, java.lang.String)
   */
  @Override
  public boolean verifyHash(String plainText, String hash) {
    boolean result = false;
    if (plainText != null && hash != null) {
      Matcher matcher = HASH_PATTERN.matcher(hash);
      if (matcher.matches()) {
        if (getHashTypeCode().equals(matcher.group(1))) {
          int rounds = (matcher.group(2) == null) ? getDefaultRoundCount() : Integer.valueOf(matcher.group(3));
          String salt = matcher.group(4);
          return hash.equals(hashPassword(plainText, salt, rounds));
        }
      }
    }
    return result;
  }

}
