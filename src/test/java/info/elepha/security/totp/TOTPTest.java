package info.elepha.security.totp;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;


@SuppressWarnings("javadoc")
public class TOTPTest {

	private static final String rfcSecret = "12345678901234567890";
	private static final int rfcInterval = 30;
	private static final int rfcSize = 8;
	private static final long rfcTime[] = {59L, 1111111109L, 1111111111L,
            1234567890L, 2000000000L, 20000000000L};
	private static final long rfcCode[] = {94287082, 7081804, 14050471,
		89005924, 69279037, 65353130};
	
	@Test
	public void testDefaultGenerateAndVerify() throws Exception {
		TOTP totp = new TOTP();
		byte[] secret = TOTPSecret.generate();
		
		int code = totp.generate(secret);
		boolean valid = totp.validate(secret, code);
		assertTrue(valid);
	}
	
	@Test
	// TODO: create black box test?
	public void testRfcCompliancy() throws Exception {
		TOTP totp = new TOTP(TOTP.DEFAULT_ALGORITHM, rfcInterval, rfcSize, TOTP.DEFAULT_STEPS);
		for (int i = 0; i < rfcTime.length; i++) {
			long time = rfcTime[i] / rfcInterval;
			int code = totp.generate(rfcSecret.getBytes(), time);
			assertEquals(rfcCode[i], code);
		}
	}
	
}
