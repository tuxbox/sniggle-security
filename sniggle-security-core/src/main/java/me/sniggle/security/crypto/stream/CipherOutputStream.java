package me.sniggle.security.crypto.stream;

import java.io.IOException;
import java.io.OutputStream;

import javax.crypto.Cipher;

/**
 * This class simplifies the output of encrypted data providing a wrapper for an
 * OutputStream and encrypting all the data as it is written to be target stream
 * 
 * @author iulius
 * @since 0.0.1
 * 
 */
public class CipherOutputStream extends OutputStream {

  private final OutputStream targetStream;
  private final Cipher cipher;
  private final byte[] buffer;
  private int bytesWrittenInBlock = 0;

  /**
   * constructor
   * 
   * @param targetStream
   *          the underlaying target of the encrypted data stream
   * @param cipher
   *          the cipher to be used for encryption
   * @param blockSize
   *          the block size (in bytes) of the required by the key (e.g.
   *          256bytes for a 2048bit encryption key)
   */
  public CipherOutputStream(OutputStream targetStream, Cipher cipher, int blockSize) {
    super();
    this.targetStream = targetStream;
    this.cipher = cipher;
    this.buffer = new byte[blockSize - 11];
  }

  /**
   * convenience method to append the entire byte array to the buffer
   * 
   * @param bs
   *          the array to be appended to the buffer
   * @throws IOException
   */
  private void appendToBuffer(byte[] bs) throws IOException {
    appendToBuffer(bs, 0, bs.length);
  }

  /**
   * appends the given byte array from the specified offset up to the given
   * length (or the maximum length of the array) to the buffer
   * 
   * @param bs
   *          the bytes to be appended
   * @param offset
   *          the offset from which the bytes are read
   * @param length
   *          the maximum length to be written (will have no effect if offset +
   *          length exceeds the length of the byte array)
   * @throws IOException
   */
  private void appendToBuffer(byte[] bs, int offset, int length) throws IOException {
    for (int i = offset; i < (offset + length) && i < bs.length; i++) {
      appendToBuffer(bs[i]);
    }
  }

  /**
   * appends a single byte to the buffer in order to allow the encryption of an
   * entire block of data at once.<br>
   * <br>
   * Once the buffer is filled completely it will be encrypted and flushed to
   * the underlying target stream.
   * 
   * @param b
   *          the byte to be appended to the buffer
   * @throws IOException
   */
  private void appendToBuffer(byte b) throws IOException {
    if (bytesWrittenInBlock < buffer.length) {
      buffer[bytesWrittenInBlock] = b;
      bytesWrittenInBlock++;
    } else if (bytesWrittenInBlock == buffer.length) {
      try {
        byte[] encrypted = cipher.doFinal(buffer);
        targetStream.write(encrypted);
        bytesWrittenInBlock = 0;
        appendToBuffer(b);
      } catch (Exception e) {// IllegalBlockSizeException | BadPaddingException
                             // | IOException e) {
        throw new IOException(e);
      }
    }
  }

  /**
   * encrypts the remaining buffer and write it to the target stream
   * 
   * @throws IOException
   */
  private void flushBuffer() throws IOException {
    byte[] encrypted;
    try {
      encrypted = cipher.doFinal(buffer, 0, bytesWrittenInBlock);
      bytesWrittenInBlock = 0;
      targetStream.write(encrypted);
    } catch (Exception e) { // IllegalBlockSizeException | BadPaddingException |
                            // IOException e) {
      throw new IOException(e);
    }
  }

  /**
   * works like the write method, but also buffers the given byte before it is
   * encrypted to encrypt entire blocks of data
   * 
   * @see java.io.OutputStream#write(int)
   */
  @Override
  public void write(int b) throws IOException {
    appendToBuffer((byte) b);
  }

  /**
   * works like the underlying target stream method, but may buffer (parts) of
   * the given byte array prior to encrypting it and writing it to the target
   * stream
   * 
   * @see java.io.OutputStream#write(byte[])
   */
  @Override
  public void write(byte[] b) throws IOException {
    appendToBuffer(b);
  }

  /**
   * works like the output stream method, but may buffer parts of the array in
   * order to encrypt an entire block
   * 
   * @see java.io.OutputStream#write(byte[], int, int)
   */
  @Override
  public void write(byte[] b, int offset, int length) throws IOException {
    appendToBuffer(b, offset, length);
  }

  /**
   * flushes the buffer by encrypting the remaining parts and later flushing the
   * target stream
   * 
   * @see java.io.OutputStream#flush()
   */
  @Override
  public void flush() throws IOException {
    flushBuffer();
    targetStream.flush();
  }

  /**
   * executes {@link #flush()} and closes the underlying stream as well
   * 
   * @see java.io.OutputStream#close()
   */
  @Override
  public void close() throws IOException {
    flush();
    targetStream.close();
  }

}
