package info.elepha.security.totp;

import java.util.Arrays;
import java.util.Random;

import org.apache.commons.codec.binary.Base32;

/**
 * Utility class for generating TOTP Secrets
 * 
 * @author Gregor "hrax" Magdolen
 */
public abstract class TOTPSecret {

	private static final Random rand = new Random();
	
	/**
	 * Generates random 20 bytes long TOTP Secret
	 * 
	 * @return generated secret
	 */
	public static final byte[] generate() {
		int size = 20;
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
	public static final String encode(byte[] secret) {
		return new String(new Base32().encode(secret));
	}
	
	/**
	 * Decodes Base32 TOTP Secret to bytes
	 * 
	 * @param secret the secret to use
	 * @return decoded secret
	 * @see Base32
	 */
	public static final byte[] decode(String secret) {
		return new Base32().decode(secret);
	}
	
}
