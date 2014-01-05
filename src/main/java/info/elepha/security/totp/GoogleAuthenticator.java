package info.elepha.security.totp;

/**
 * Utility class for Google Authenticator
 * @author Gregor "hrax" Magdolen
 */
public abstract class GoogleAuthenticator {

	/**
	 * Returns QR code url that can be opened in browser and scanned by application
	 * 
	 * @param username the user name
	 * @param host the host
	 * @param secret the secret
	 * @return QR code url
	 * @see TOTPSecret#generate()
	 * @see TOTPSecret#encode(byte[])
	 */
	public static final String getQRUrl(String username, String host, String secret) {
		String format = "https://www.google.com/chart?chs=200x200&chld=M%%7C0&cht=qr&chl=otpauth://totp/%s@%s%%3Fsecret%%3D%s";
		return String.format(format, username, host, secret);
	}
	
	
}
