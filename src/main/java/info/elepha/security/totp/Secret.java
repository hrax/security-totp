package info.elepha.security.totp;

import java.util.Arrays;
import java.util.Random;

import org.apache.commons.codec.binary.Base32;

/**
 * Utility class for generating TOTP Secrets
 * 
 * @author Gregor "hrax" Magdolen
 */
public abstract class Secret {

	private static final Random rand = new Random();
	
	public static final int SIZE_20B = 20;
	
	public static final int SIZE_32B = 32;
	
	public static final int SIZE_64B = 64;
	
	/**
	 * Generates random 20 bytes
	 * 
	 * @return generated secret
	 */
	public static final byte[] generate() {
		return generate(SIZE_20B);
	}
	
	/**
	 * Generates random bytes of given size
	 * 
	 * @return generated secret
	 */
	public static final byte[] generate(int size) {
		byte[] b = new byte[size];
		rand.nextBytes(b);
		return Arrays.copyOf(b, size);
	}
	
	/**
	 * Encodes TOTP Secret to Base32
	 * 
	 * @param secret the secret to use
	 * @return encoded secret
	 * @see Base32
	 */
	public static final String toBase32(byte[] secret) {
		return new String(new Base32().encode(secret));
	}
	
	/**
	 * Decodes Base32 TOTP Secret to bytes
	 * 
	 * @param secret the secret to use
	 * @return decoded secret
	 * @see Base32
	 */
	public static final byte[] fromBase32(String secret) {
		return new Base32().decode(secret);
	}
	
}
