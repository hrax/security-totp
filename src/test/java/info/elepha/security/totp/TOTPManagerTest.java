package info.elepha.security.totp;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.mockito.Mockito;


@SuppressWarnings("javadoc")
public class TOTPManagerTest {

	private static final String rfcSecret = "12345678901234567890";
	private static final int rfcInterval = 30;
	private static final int rfcSize = 8;
	private static final long rfcTime[] = {59L, 1111111109L, 1111111111L,
            1234567890L, 2000000000L, 20000000000L}; // time in seconds
	private static final String rfcCode[] = {"94287082", "07081804", "14050471",
		"89005924", "69279037", "65353130"};
	
	
	@Test
	public void testTimeIntervalGeneration() throws Exception {
		TOTPManager manager = new TOTPManager();
		long[] times = {5L, 30L, 31L, 60L};
		
		assertEquals(0, manager.getTimeInterval(times[0] * 1000));
		assertEquals(1, manager.getTimeInterval(times[1] * 1000));
		assertEquals(1, manager.getTimeInterval(times[2] * 1000));
		assertEquals(2, manager.getTimeInterval(times[3] * 1000));
	}
	
	@Test
	public void testRfcCompliancy() throws Exception {
		TOTPManager totp = new TOTPManager(rfcInterval, rfcSize, 1);
		for (int i = 0; i < rfcTime.length; i++) {
			long t = rfcTime[i] * 1000;
			String code = totp.generateOTP(rfcSecret.getBytes(), totp.getTimeInterval(t));
			assertEquals(rfcCode[i], code);
		}
	}
	
	@Test
	public void testBackwardsValidation() throws Exception {
		TOTPManager manager = new TOTPManager();
		byte[] secret = rfcSecret.getBytes();
		long itvls[] = {0L, 1L, 1L, 2L}; // see #testTimeIntervalGeneration
		
		List<String> codes = new ArrayList<String>(); // holds generated code for each interval
		
		for (long i : itvls) {
			codes.add(manager.generateOTP(secret, i));
		}
		
		// validate that the codes are not the same
		assertEquals(4, codes.size()); // has 4 generated codes
		assertFalse(codes.get(0).equals(codes.get(1)));
		assertFalse(codes.get(0).equals(codes.get(2)));
		assertFalse(codes.get(0).equals(codes.get(3)));
		assertFalse(codes.get(3).equals(codes.get(1)));
		assertFalse(codes.get(3).equals(codes.get(2)));
		assertTrue(codes.get(1).equals(codes.get(2)));
	}
	
	@Test
	public void testMockBackwardsValidation() throws Exception {
		byte[] secret = rfcSecret.getBytes();
		
		TOTPManager spy = Mockito.spy(new TOTPManager(rfcInterval, rfcSize, 1));
		Mockito.when(spy.getCurrentTimeInterval()).thenReturn(1L, 2L, 2L, 3L, 3L, 4L); // for current time 59L, 60L, 90L, 120L
		Mockito.when(spy.getSteps()).thenReturn(1, 0, 1, 2);
				
		// generate first code for interval 1
		String code = spy.generate(secret);
		assertEquals(rfcCode[0], code);
		
		// run validation for interval 2 and steps 1
		assertTrue(spy.validate(secret, code));
		
		// run validation for interval 2 and steps 0
		assertFalse(spy.validate(secret, code));
		
		// run validation for interval 3 and steps 1
		assertFalse(spy.validate(secret, code));
		
		// run validation for interval 3 and steps 2
		assertTrue(spy.validate(secret, code));
		
		// run validation for interval 4 and steps 2
		assertFalse(spy.validate(secret, code));
	}
	
	
}
