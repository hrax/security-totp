TOTP - Time-Based One-Time Password Algorithm Library
=============

[RFC6238](http://tools.ietf.org/html/rfc6238) Java implementation that is compatibile with Google Authenticator Application.

Provides utility class for generating links for QR codes that can be scanned by Goodle Authenticator. It is also capable of generating authentication codes as well as their verification.

It is very easy to use:

	TOTP totp = new TOTP();
	
	byte[] secret = TOTPSecret.generate();
		
	String encoded = TOTPSecret.encode(secret);
	String qr = GoogleAuthenticator.getQRUrl("jdoe", "example.com", encoded);
	
	byte[] decoded = TOTPSecret.decode(key);
	int code = totp.generate(secret);
	boolean valid = totp.validate(decoded, code);
	
Demo available for preview at: http://security-totp.appspot.com/
	