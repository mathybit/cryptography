package pca.cs.crypto;


import java.math.BigInteger;
import java.util.Random;
import pca.cs.crypto.rsa.*;
import pca.cs.jna.gmp.GMP;

import com.google.common.base.Stopwatch;

/**
 * Run encryption/decryption sanity checks for the Java and GMP implementations of RSA.
 * Also run a benchmark test to compare running times.
 * 
 * @author Adrian Pacurar, Feb 2, 2018
 */
public class TestRSA {
	public static void main(String[] args) {
		Random r = new Random();
		Stopwatch sw = Stopwatch.createUnstarted();
		int[] bits = { 32, 64, 128, 256, 512, 1024 };
		int operationCount;
		
		
		/**
		 * Test Java operations
		 */
		operationCount = 500;
		System.out.println("Java operation test ("+ operationCount + " times):");
		for (int i = 0; i < bits.length; i++) {
			System.out.print("   " + bits[i] + " bits: ");
			int count = operationCount;
			r = new Random(42);
			
			RSA rsa = new RSAJavaImpl(bits[i]);
			BigInteger message, cipher, message_dec;
			
			while (count > 0) {
				int messagebits = rsa.getPKn().bitLength() - 1;
				message = new BigInteger(messagebits, r);
				cipher = rsa.encrypt(message);
				message_dec = rsa.decrypt(cipher);
				
				if(!message.equals(message_dec)) {
					System.err.println("FAILED");
					System.exit(0);
				}
				count--;
			}
			System.out.println("PASSED");
		}
		
		
		/**
		 * Test GMP operations
		 */
		bits = new int[] { 16, 32, 64, 128, 256, 512, 1024, 2048 };
		operationCount = 1000;
		System.out.println("GMP operation test ("+ operationCount + " times):");
		for (int i = 0; i < bits.length; i++) {
			System.out.print("   " + bits[i] + " bits: ");
			int count = operationCount;
			r = new Random(42);
			
			RSA rsa = new RSAGMPImpl(bits[i]);
			BigInteger message, cipher, message_dec;
			
			while (count > 0) {
				int messagebits = rsa.getPKn().bitLength() - 1;
				message = new BigInteger(messagebits, r);
				cipher = rsa.encrypt(message);
				message_dec = rsa.decrypt(cipher);
				
				if(!message.equals(message_dec)) {
					System.err.println("FAILED");
					System.exit(0);
				}
				count--;
			}
			System.out.println("PASSED");
		}
		
		
		
		/**
		 * Test object creation speed for specified bit length
		 */
		bits = new int[] { 64, 128, 256, 512, 1024 };
		operationCount = 200;
		System.out.println("RSA creation ("+ operationCount + " times):");
		for (int i = 0; i < bits.length; i++) {
			System.out.print("   " + bits[i] + " bits | ");
			int count = operationCount;
			r = new Random(42);
			
			sw.start();
			while (count > 0) {
				new RSAJavaImpl(bits[i]);
				count--;
			}
			sw.stop();
			System.out.print("Java: " + sw);
			sw.reset();
			
			count = operationCount;
			sw.start();
			while (count > 0) {
				new RSAGMPImpl(bits[i]);
				count--;
			}
			sw.stop();
			System.out.print(" | GMP: " + sw);
			sw.reset();
			System.out.println();
		}
		System.out.println("Done.");
		
		
		/**
		 * Test encryption/decryption cycles
		 */
		bits = new int[] { 32, 64, 128, 256, 512, 1024, 2048 };
		operationCount = 1000;
		System.out.println("RSA encryption/decryption ("+ operationCount + " times):");
		for (int i = 0; i < bits.length; i++) {
			System.out.print("   " + bits[i] + " bits | ");
			int count = operationCount;
			r = new Random(42);
			RSA rsajava = new RSAJavaImpl(bits[i]);
			RSA rsagmp = new RSAGMPImpl(bits[i]);
			
			int messagebits = rsajava.getPKn().bitLength() - 1;
			BigInteger message = new BigInteger(messagebits, r);
			BigInteger cipher, message_dec;
			
			sw.start();
			while (count > 0) {
				cipher = rsajava.encrypt(message);
				message_dec = rsajava.decrypt(cipher);
				
				if (!message.equals(message_dec)) {
					System.err.println("Java decryption failed.");
					System.exit(-1);
				}
				count--;
			}
			sw.stop();
			System.out.print("Java: " + sw);
			sw.reset();
			
			
			messagebits = rsagmp.getPKn().bitLength() - 1;
			message = new BigInteger(messagebits, r);
			count = operationCount;
			sw.start();
			while (count > 0) {
				cipher = rsagmp.encrypt(message);
				message_dec = rsagmp.decrypt(cipher);
				
				if (!message.equals(message_dec)) {
					System.err.println("GMP decryption failed.");
					System.exit(-1);
				}
				count--;
			}
			sw.stop();
			System.out.print(" | GMP: " + sw);
			sw.reset();
			System.out.println();
		}
		System.out.println("Done.");
	}

}
