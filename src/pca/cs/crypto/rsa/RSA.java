package pca.cs.crypto.rsa;

import java.math.BigInteger;

/**
 * Unpadded RSA algorithm
 * 
 * @author Adrian Pacurar, Feb 2, 2018
 *
 */
public interface RSA {
	public BigInteger encrypt(BigInteger message);
	public BigInteger encrypt(String message);
	public BigInteger encrypt(long message);
	public BigInteger decrypt(BigInteger cipher);
	public BigInteger decrypt(String cipher);
	public BigInteger decrypt(long cipher);
	
	public BigInteger getPKn();
	public BigInteger getPKe();
	public void print();
}
