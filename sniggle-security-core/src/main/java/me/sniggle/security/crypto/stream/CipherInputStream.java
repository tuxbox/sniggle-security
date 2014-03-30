/**
 * 
 */
package me.sniggle.security.crypto.stream;

import java.io.IOException;
import java.io.InputStream;

import javax.crypto.Cipher;

/**
 * A convenience class used to decrypt an encrypted data stream immediately
 * using asymmetric encryption mechanisms
 * 
 * Automatically reads the appropriate block sizes for the given private key
 * length
 * 
 * @author iulius
 * @since 0.0.1
 * 
 */
public class CipherInputStream extends InputStream {

  private final InputStream sourceInputStream;
  private final Cipher cipher;
  private final byte[] buffer;
  private int encryptedBytesRead;
  private byte[] plainBuffer;
  private int plainBufferReadIndex = -2;

  /**
   * the constructor
   * 
   * @param sourceInputStream
   *          the encrypted source data stream
   * @param cipher
   *          the cipher to be used to decrypt the data
   * @param blockSize
   *          the block size to be read and decrypt with each operation
   */
  public CipherInputStream(InputStream sourceInputStream, Cipher cipher, int blockSize) {
    this.sourceInputStream = sourceInputStream;
    this.cipher = cipher;
    this.buffer = new byte[blockSize];
    this.plainBuffer = new byte[blockSize - 11];
  }

  /**
   * convenience method used to read encrypted data in block and buffer the
   * plain data in the appropriate array
   * 
   * @throws IOException
   */
  private void readEncrypted() throws IOException {
    try {
      if (plainBufferReadIndex == -2 || plainBufferReadIndex == plainBuffer.length) {
        encryptedBytesRead = sourceInputStream.read(buffer);
        plainBufferReadIndex = -1;
        if (encryptedBytesRead != -1) {
          plainBuffer = cipher.doFinal(buffer);
          plainBufferReadIndex = 0;
        }
      }
    } catch (Exception e) {// IllegalBlockSizeException | BadPaddingException
      throw new IOException(e);
    }
  }

  /**
   * this method reads a block of encrypted data an returns only the next
   * decrypted byte in the stream
   * 
   * @see {@link InputStream#read()}
   */
  @Override
  public int read() throws IOException {
    readEncrypted();
    if (plainBufferReadIndex < plainBuffer.length && plainBufferReadIndex > -1) {
      byte result = plainBuffer[plainBufferReadIndex];
      plainBufferReadIndex++;
      return result;
    } else if (plainBufferReadIndex != -1) {
      return read();
    }
    return plainBufferReadIndex;
  }
  
  /**
   * reads encrypted data and fills the given byte array with the decrypted data
   * upto the length of the byte array. returns the number of plain bytes
   * written to the array
   * 
   * @see {@link InputStream#read(byte[])}
   */
  @Override
  public int read(byte b[]) throws IOException {
    int bytesRead = 0;
    do {
      readEncrypted();
      while (plainBufferReadIndex > -1 && plainBufferReadIndex < plainBuffer.length && bytesRead < b.length) {
        b[bytesRead] = plainBuffer[plainBufferReadIndex];
        plainBufferReadIndex++;
        bytesRead++;
      }
    } while (bytesRead < b.length && bytesRead > 0 && encryptedBytesRead != -1);
    return (bytesRead == 0) ? -1 : bytesRead;
  }

  /**
   * reads the encrypted data and writes the decrypted data into the byte array
   * from the given offset at the maximum length specified. returns the number
   * of actually read plain data bytes
   * 
   * @see {@link InputStream#read(byte[], int, int)}
   */
  @Override
  public int read(byte b[], int off, int len) throws IOException {
    int bytesRead = 0;
    do {
      readEncrypted();
      while (plainBufferReadIndex > -1 && plainBufferReadIndex < plainBuffer.length && bytesRead < len && (bytesRead + off) < b.length) {
        b[off + bytesRead] = plainBuffer[plainBufferReadIndex];
        plainBufferReadIndex++;
        bytesRead++;
      }
    } while (bytesRead < len && (off + bytesRead) < b.length && encryptedBytesRead != -1);
    return (bytesRead == 0) ? -1 : bytesRead;
  }

}
