TOTP - Time-Based One-Time Password Algorithm Library
=============

[RFC6238](http://tools.ietf.org/html/rfc6238) Java implementation that is compatibile with Google Authenticator Application.

Provides utility class for generating links for QR codes that can be scanned by Goodle Authenticator. It is also capable of generating authentication codes as well as their verification.

It is very easy to use:

	TOTPManager manager = new TOTPManager();
	
	byte[] secret = Secret.generate();
	
	// generate Google Authenticator QR Code
	String encoded = Secret.toBase32(secret);
	String qr = GoogleAuthenticator.getQRUrl("jdoe", "example.com", encoded);
	
	// generate TOTP code
	int code = manager.generate(secret);
	boolean valid = manager.validate(secret, code); // by default code is valid for 60 seconds
	
Demo available for preview at: http://security-totp.appspot.com/
	
