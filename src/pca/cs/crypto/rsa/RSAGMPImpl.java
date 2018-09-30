package pca.cs.crypto.rsa;

import java.math.BigInteger;
import java.util.Random;

import pca.cs.jna.gmp.GMP;//libgmp


/**
 * An implementation of the RSA algorithm using native libgmp and JNA
 * 
 * @author Adrian Pacurar, Feb 6, 2018
 *
 */
public class RSAGMPImpl implements RSA {
	private int certainty = 20;
	private BigInteger p;//prime 1
	private BigInteger q;//prime 2
	private BigInteger n;//p * q
	private BigInteger phi;//Euler's phi(n)
	private BigInteger e;//public key
	private BigInteger d;//private key
	private static final BigInteger ONE = BigInteger.ONE;
	private Random r;
	
	/**
	 * Constructors where only 2 primes are specified
	 * Then e will be the first nonunit invertible element modulo phi.
	 * 
	 * We also check for the primality of p,q, with specified certainty set
	 * in the class fields. The probability threshold is 1 - 1/2^certainty.
	 * 
	 * Below is a small list of certainty values and their probability thresholds:
	 * 4  -> 93.75% (not recommended)
	 * 5  -> 96.9% (not recommended)
	 * 6  -> 98.4%
	 * 7  -> 99.2%
	 * 8  -> 99.6%
	 * 9  -> 99.8%
	 * 10 -> 99.9%
	 */
	public RSAGMPImpl(BigInteger prime1, BigInteger prime2) {
		r = new Random();
		p = prime1;
		q = prime2;
		initializeWithoutE();
	}
	public RSAGMPImpl(String prime1, String prime2) {
		this(new BigInteger(prime1), new BigInteger(prime2));
	}
	public RSAGMPImpl(long prime1, long prime2) {
		this(  (new Long(prime1)).toString(), (new Long(prime2)).toString()  );
	}
	
	/**
	 * Constructors where p1, p2, and e is specified
	 * 
	 * We also check for the primality of p,q, with specified certainty set
	 * in the class fields. The probability threshold is 1 - 1/2^certainty.
	 * 
	 * Below is a small list of certainty values and their probability thresholds:
	 * 4  -> 93.75% (not recommended)
	 * 5  -> 96.9% (not recommended)
	 * 6  -> 98.4%
	 * 7  -> 99.2%
	 * 8  -> 99.6%
	 * 9  -> 99.8%
	 * 10 -> 99.9%
	 */
	public RSAGMPImpl(BigInteger prime1, BigInteger prime2, BigInteger pkey) {
		r = new Random();
		p = prime1;
		q = prime2;
		e = pkey;
		initializeWithE();
	}
	public RSAGMPImpl(String prime1, String prime2, String pkey) {
		this(new BigInteger(prime1), new BigInteger(prime2), new BigInteger(pkey));
	}
	public RSAGMPImpl(long prime1, long prime2, long pkey) {
		this(  (new Long(prime1)).toString(), (new Long(prime2)).toString(), (new Long(pkey)).toString()  );
	}
	
	/**
	 * Allows the user the option to construct a RSA object where p and q have bits/2
	 * bits total (so that their product has 'bits' bits). This is really the main 
	 * constructor, and the best way to use this object. The other constructors are
	 * for testing (or for doing your homework).
	 */
	public RSAGMPImpl(int bits) {
		r = new Random();
		int adjustedBitLength = (int) Math.ceil(((double)bits)/2);
		BigInteger lowerLimit = new BigInteger(adjustedBitLength, r);
		//p = new BigInteger(adjustedBitLength, certainty, r);
		//q = new BigInteger(adjustedBitLength, certainty, r);
		p = GMP.nextPrime(lowerLimit);
		lowerLimit = new BigInteger(adjustedBitLength, r);
		q = GMP.nextPrime(lowerLimit);
		initializeWithoutE();
	}
	
	
	/**
	 * Initialization code that is used by all the constructors
	 */
	private void initializeWithoutE() {
		if (GMP.isProbablePrime(p, certainty) == 0 || GMP.isProbablePrime(q, certainty) == 0) {
			System.out.println("Primality testing failed, exiting.");
			System.exit(0);
		}
		
		//when adding/multiplying, native GMP calls are slower than Java due to overhead
		n = p.multiply(q); //GMP.multiply(p, q) is slower due to overhead
		phi = (p.subtract(ONE)).multiply(q.subtract(ONE));
		
		e = new BigInteger(phi.bitLength() - 1, r);
		while (e.compareTo(ONE) <= 0 || !GMP.gcd(phi, e).equals(ONE) || e.compareTo(phi) >= 0) {
			e = new BigInteger(phi.bitLength() - 1, r);
		}
		d = GMP.modInverse(e, phi);//private key
	}
	private void initializeWithE() {
		if (GMP.isProbablePrime(p, certainty) == 0 || GMP.isProbablePrime(q, certainty) == 0) {
			System.out.println("Primality testing failed, exiting.");
			System.exit(0);
		}
		//when adding/multiplying, native GMP calls are slower than Java due to overhead
		n = p.multiply(q); //GMP.multiply(p, q) is slower due to overhead
		phi = (p.subtract(ONE)).multiply(q.subtract(ONE));
		
		if (!GMP.gcd(phi, e).equals(ONE)) {
			System.out.println("The specified pkey is not relatively prime to phi, exiting.");
			System.exit(0);
		}
		d = GMP.modInverse(e, phi);//private key
	}
	
	
	/**
	 * The RSA encryption method. Returns the result as a BigInteger. The specified
	 * message must be a BigInteger.
	 */
	public BigInteger encrypt(BigInteger message) {
		return GMP.modPowInsecure(message, e, n);//message.modPow(e, n);
	}
	public BigInteger encrypt(String message) {
		return encrypt(new BigInteger(message));
	}
	public BigInteger encrypt(long message) {
		return encrypt((new Long(message)).toString());
	}
	
	/**
	 * The RSA decryption method. Returns the result as a BigInteger. The specified
	 * ciphertext must be a BigInteger.
	 */
	public BigInteger decrypt(BigInteger cipher) {
		return GMP.modPowInsecure(cipher, d, n);//cipher.modPow(d, n);
	}
	public BigInteger decrypt(String cipher) {
		return decrypt(new BigInteger(cipher));
	}
	public BigInteger decrypt(long cipher) {
		return decrypt((new Long(cipher)).toString());
	}
	
	
	/**
	 * Some methods used for debugging (or for doing your homework)
	 */
	public BigInteger getPKn() {
		return n;
	}
	public BigInteger getPKe() {
		return e;
	}
	public BigInteger getSK() {
		return d;
	}
	public void print() {
		System.out.println("========== RSA Object Status =========");
		System.out.println("  p = " + p);
		System.out.println("  q = " + q);
		System.out.println("  n = " + n);
		System.out.println("phi = " + phi);
		System.out.println("  e = " + e);
		System.out.println("  d = " + d);
	}
}
