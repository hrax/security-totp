package info.elepha.security.totp;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * <p>TOTP: Time-Based One-Time Password Algorithm
 * 
 * <p>Bean to easily generate TOTP for 2 step authentication. Is <a href="http://tools.ietf.org/html/rfc6238">RFC6238</a> 
 * compliant and it's default configuration is also compatible with <a href="https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2&hl=en">Google Authenticator</a>.
 * 
 * <p>This allows for easy 2 step authentication integration with own service 
 * without necessity to write own code generating application 
 * 
 * <p>TODO: Allow generation of backup codes
 * 
 * @author Gregor "hrax" Magdolen
 * @version $Id$
 */
public final class TOTP {

	private static final int[] DIGITS_POWER
    // 0  1   2    3     4      5       6        7         8
    = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};
	
	/**
	 * Default algorithm (Google Authenticator Compatible)
	 */
	public static final String DEFAULT_ALGORITHM = "HmacSHA1";
	
	/**
	 * Default time interval in seconds (Google Authenticator Compatible)
	 */
	public static final int DEFAULT_INTERVAL = 30;
	
	/**
	 * Default code length (Google Authenticator Compatible)
	 */
	public static final int DEFAULT_LENGTH = 6;
	
	private final String algorithm;
	
	private final int interval;
	
	private final int length;
	
	/**
	 * Create default TOTP instance that is Google Authenticator compatible
	 */
	public TOTP() {
		this(DEFAULT_ALGORITHM, DEFAULT_INTERVAL, DEFAULT_LENGTH);
	}
	
	/**
	 * Create new TOTP instance with own time interval
	 * 
	 * @param interval the time interval to use
	 */
	public TOTP(int interval) {
		this(DEFAULT_ALGORITHM, interval, DEFAULT_LENGTH);
	}
	
	/**
	 * Create new TOTP instance with own configuration
	 * 
	 * @param algorithm the algorithm to use; available HmacSHA1, HmacSHA256, HmacSHA512
	 * @param interval the time interval in seconds to use
	 * @param length the code length to use; must be between 1 and 8
	 */
	public TOTP(String algorithm, int interval, int length) {
		this.algorithm = algorithm;
		this.interval = interval;
		this.length = length;
		
		if (length > DIGITS_POWER.length || length < 1) {
			throw new IllegalArgumentException("Length must be between 1 and 8");
		}
	}
	
	/**
	 * @return the algorithm being used
	 */
	public String getAlgorithm() {
		return algorithm;
	}
	
	/**
	 * @return the interval being used
	 */
	public int getInterval() {
		return interval;
	}
	
	/**
	 * @return the length being used
	 */
	public int getLength() {
		return length;
	}
	
	/**
	 * Generates TOTP code for current time interval
	 * 
	 * @param secret the secret to use
	 * @return generated code
	 * @see TOTPSecret#generate()
	 */
	public int generate(byte[] secret) {
		return generate(secret, getCurrentTimeInterval());
	}
	
	/**
	 * Validates TOTP code for current time interval
	 * 
	 * @param secret the secret to use
	 * @param code the code to validate
	 * @return true if code is valid
	 * @see TOTPSecret#generate()
	 */
	public boolean validate(byte[] secret, int code) {
		int win = getInterval();
		long t = getCurrentTimeInterval();
		
		for (int i = -win; i <= win; ++i) {
			int hash = generate(secret, t + i);
			if (hash == code) {
				return true;
			}
		}
		
		return false;
	}
	
	/**
	 * Generates TOTP code for give time
	 * 
	 * @param secret the secret to use
	 * @param time the time to use (in seconds!)
	 * @return generated code
	 * @see TOTPSecret#generate()
	 */
	int generate(byte[] secret, long time) {
		byte[] text = ByteBuffer.allocate(8).putLong(time).array();
		byte[] hash = getSha(secret, text);
		
		int off = hash[hash.length-1] & 0xf;
		int bin = ((hash[off] & 0x7f) << 24) | ((hash[off + 1] & 0xff) << 16) | ((hash[off + 2] & 0xff) << 8) | (hash[off + 3] & 0xff);

		return bin % DIGITS_POWER[getLength()];
	}
	
	private byte[] getSha(byte[] key, byte[] text) {
		try {
			Mac mac = Mac.getInstance(getAlgorithm());
			SecretKeySpec spec = new SecretKeySpec(key, "RAW");
			mac.init(spec);
			return mac.doFinal(text);
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException(e);
		}
	}
	
	private long getCurrentTimeInterval() {
		return (System.currentTimeMillis() / 1000) / getInterval();
	}
	
}
