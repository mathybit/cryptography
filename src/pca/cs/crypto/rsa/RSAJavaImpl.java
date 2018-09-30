package pca.cs.crypto.rsa;

import java.math.BigInteger;
import java.util.Random;
import java.util.LinkedList;

/**
 * An implementation of the RSA algorithm using Java's BigInteger
 * 
 * @author Adrian Pacurar, Feb 2, 2018
 *
 */
public class RSAJavaImpl implements RSA {
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
	public RSAJavaImpl(BigInteger prime1, BigInteger prime2) {
		r = new Random();
		p = prime1;
		q = prime2;
		initializeWithoutE();
	}
	public RSAJavaImpl(String prime1, String prime2) {
		this(new BigInteger(prime1), new BigInteger(prime2));
	}
	public RSAJavaImpl(long prime1, long prime2) {
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
	public RSAJavaImpl(BigInteger prime1, BigInteger prime2, BigInteger pkey) {
		r = new Random();
		p = prime1;
		q = prime2;
		e = pkey;
		initializeWithE();
	}
	public RSAJavaImpl(String prime1, String prime2, String pkey) {
		this(new BigInteger(prime1), new BigInteger(prime2), new BigInteger(pkey));
	}
	public RSAJavaImpl(long prime1, long prime2, long pkey) {
		this(  (new Long(prime1)).toString(), (new Long(prime2)).toString(), (new Long(pkey)).toString()  );
	}
	
	
	/**
	 * Allows the user the option to construct a RSA object where p and q have bits/2
	 * bits total (so that their product has 'bits' bits). This is really the main 
	 * constructor, and the best way to use this object. The other constructors are
	 * for testing (or for doing your homework).
	 */
	public RSAJavaImpl(int bits) {
		r = new Random();
		int adjustedBitLength = (int) Math.ceil(((double)bits)/2);
		p = new BigInteger(adjustedBitLength, certainty, r);
		q = new BigInteger(adjustedBitLength, certainty, r);
		initializeWithoutE();
	}
	
	
	/**
	 * Initialization code that is used by all the constructors
	 */
	private void initializeWithoutE() {
		if (! (p.isProbablePrime(certainty) && q.isProbablePrime(certainty))) {
			System.out.println("Primality testing failed, exiting.");
			System.exit(0);
		}
		n = p.multiply(q);
		phi = (p.subtract(ONE)).multiply(q.subtract(ONE));
		
		e = new BigInteger(phi.bitLength() - 1, r);
		while (e.compareTo(ONE) <= 0 || !phi.gcd(e).equals(ONE) || e.compareTo(phi) >= 0) {
			e = new BigInteger(phi.bitLength() - 1, r);
		}
		//d = inverse(e, phi);//private key
		d = e.modInverse(phi);
	}
	private void initializeWithE() {
		if (! (p.isProbablePrime(certainty) && q.isProbablePrime(certainty))) {
			System.out.println("Primality testing failed, exiting.");
			System.exit(0);
		}
		n = p.multiply(q);
		phi = (p.subtract(ONE)).multiply(q.subtract(ONE));
		if (!phi.gcd(e).equals(ONE)) {
			System.out.println("The specified pkey is not relatively prime to phi, exiting.");
			System.exit(0);
		}
		//d = inverse(e, phi);//private key
		d = e.modInverse(phi);
	}
	
	
	/**
	 * The RSA encryption method. Returns the result as a BigInteger. The specified
	 * message must be a BigInteger.
	 */
	public BigInteger encrypt(BigInteger message) {
		return message.modPow(e, n);
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
		return cipher.modPow(d, n);
	}
	public BigInteger decrypt(String cipher) {
		return decrypt(new BigInteger(cipher));
	}
	public BigInteger decrypt(long cipher) {
		return decrypt((new Long(cipher)).toString());
	}
	
	
	/**
	 * Compute the multiplicative inverse of k modulo N using the Euclidean Algorithm,
	 * and backwards substitution method. Java also provides an implementation for this
	 * in the BigInteger class (which is probably more efficient than this).
	 */
	public static BigInteger inverse(BigInteger k, BigInteger N) {
		if (k.compareTo(N) >= 0) {
			System.out.println("k needs to be smaller than N");
			return ONE;
		}
		BigInteger a = N, b = k;
		BigInteger gcd = a.gcd(b);
		//System.out.println("gcd(" + k + ", " + N + ") = " + gcd);
		if (!gcd.equals(ONE)) {
			System.out.println(k + " is not invertible modulo " + N);
			return ONE;
		}
		
		LinkedList<BigInteger> listA = new LinkedList<BigInteger>();//"special" list
		LinkedList<BigInteger> listB = new LinkedList<BigInteger>();//contains diviors in reverse order
		BigInteger[] dr = a.divideAndRemainder(b);//dr[0] = divisor, dr[1] = remainder
		
		listB.addFirst(dr[0]);
		while (!dr[1].equals(BigInteger.ZERO)) {
			a = b;
			b = dr[1];
			dr = a.divideAndRemainder(b);
			listB.addFirst(dr[0]);
		}
		//System.out.println("B list: " + listB);
		
		//next we build the special listA, using the following recursive formula
		//A[0] = 0, A[1] = 1, and A[n] = A[n-1]*B[n-1] + A[n-2}
		//the last 2 values in listA will be the coefficients (in absolute value) for
		//the linear combination expression of the gcd(k,N)
		//the last element is related to the inverse
		listA.addLast(BigInteger.ZERO);
		listA.addLast(BigInteger.ONE);
		for (int i = 2; i <= listB.size(); i++) {
			listA.add(    (  listA.get(i-1).multiply(listB.get(i-1))  ).add(listA.get(i-2))    );
		}
		//System.out.println("A list: " + listA);
		
		//we need to check whether to use the last element, or its negative
		BigInteger inv = listA.removeLast();
		//System.out.println("inv: " + inv);
		BigInteger mult = ( k.multiply(inv) ).mod(N);
		if (mult.equals(gcd)) {
			//System.out.println("case1: " + inv.mod(N));
			return inv.mod(N);
		}
		mult = ( k.multiply(inv.negate()) ).mod(N);
		if (mult.equals(gcd)) {
			//System.out.println("case2: " + inv.negate().mod(N));
			return inv.negate().mod(N);
		}
		System.out.println("Unable to invert " + k + " modulo " + N + " for some reason.");
		return ONE;
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
