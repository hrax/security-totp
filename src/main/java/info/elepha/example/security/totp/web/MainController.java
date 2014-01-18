package info.elepha.example.security.totp.web;

import info.elepha.security.totp.GoogleAuthenticator;
import info.elepha.security.totp.TOTP;
import info.elepha.security.totp.TOTPSecret;

import java.text.DateFormat;
import java.util.Calendar;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class MainController {

	private static final String COOKIE_NAME = "security-totp";
	
	private static final String SEPARATOR = ":###:";
	
	private TOTP totp;
	
	@Autowired
	public void setTotp(TOTP totp) {
		this.totp = totp;
	}

	@ModelAttribute ("isLocalhost")
	public boolean isLocalhost(HttpServletRequest request) {
		String host = getHost(request);
		return "localhost".equalsIgnoreCase(host) || "127.0,0,1".equals(host);
	}
	
	@ModelAttribute ("request")
	public String getRequestUrl(HttpServletRequest request) {
		String url = request.getRequestURL().toString();
		if (url.endsWith("/")) {
			url = url.substring(0, url.length() - 1);
		}
		return url;
	}
	
	@ModelAttribute ("host")
	public String getHost(HttpServletRequest request) {
		return request.getServerName();
	}
	
	@ModelAttribute ("username")
	public String getUsername(HttpServletRequest request) {
		Cookie cookie = getCookie(request);
		if (cookie == null) return null;
		
		String decoded = decodeCookie(cookie);
		String[] split = decoded.split(SEPARATOR);
		if (split.length != 2) return null;
		
		return split[0];
	}
	
	@ModelAttribute ("secret")
	public String getSecret(HttpServletRequest request) {
		Cookie cookie = getCookie(request);
		if (cookie == null) return null;
		
		String decoded = decodeCookie(cookie);
		String[] split = decoded.split(SEPARATOR);
		if (split.length != 2) return null;
		
		return split[1];
	}
	
	@RequestMapping (value = {"/", ""})
	public String index(@ModelAttribute ("username") String username, @ModelAttribute ("secret") String secret, Model model, HttpServletRequest request) {
		if (StringUtils.hasText(username) && StringUtils.hasText(secret)) {
			model.addAttribute("totp", true);
			model.addAttribute("qr", GoogleAuthenticator.getQRUrl(username, getHost(request), secret));
		}
		
		return "index";
	}
	
	@RequestMapping (value = "/totp/generate", produces = "application/json")
	@ResponseBody
	public Object generate(@RequestParam (value="username", required = false) String username, @ModelAttribute ("host") String host, HttpServletRequest request, HttpServletResponse response) {
		if (!StringUtils.hasText(username)) {
			return Collections.singletonMap("error", "Username missing!");
		}
		
		byte[] key = TOTPSecret.generate();
		String secret = TOTPSecret.encode(key);
		String qr = GoogleAuthenticator.getQRUrl(username, getHost(request), secret);
		
		response.addCookie(createCookie(username, secret));
		
		Map<String,Object> map = new HashMap<String, Object>();
		map.put("username", username);
		map.put("host", host);
		map.put("secret", secret);
		map.put("qr", qr);
		return map;
	}
	
	@RequestMapping (value = "/totp/refresh", produces = "application/json")
	@ResponseBody
	public Object refresh(@ModelAttribute ("username") String username, @ModelAttribute ("secret") String secret, HttpServletResponse response) {
		Map<String,Object> map = new HashMap<String, Object>();

		if (StringUtils.hasText(username) && StringUtils.hasText(secret)) {
			response.addCookie(createCookie(username, secret));
			map.put("refreshed", true);
		} else {
			map.put("error", "No secret");
		}
		
		return map;
	}
	
	@RequestMapping (value = "/totp/destroy", produces = "application/json")
	@ResponseBody
	public Object destroy(@ModelAttribute ("username") String username, @ModelAttribute ("secret") String secret, HttpServletResponse response) {
		Map<String,Object> map = new HashMap<String, Object>();

		if (StringUtils.hasText(username) && StringUtils.hasText(secret)) {
			response.addCookie(destroyCookie(username, secret));
			map.put("destroyed", true);
		} else {
			map.put("error", "No secret");
		}
		
		return map;
	}
	
	@RequestMapping (value = "/totp/verify", produces = "application/json")
	@ResponseBody
	public Object verify(@RequestParam (value="code", required = false) Integer code, @ModelAttribute ("secret") String secret, HttpServletRequest request) {
		if (code == null) {
			return Collections.singletonMap("error", "Code missing!");
		}
		
		Map<String,Object> map = new HashMap<String, Object>();
		
		if (StringUtils.hasText(secret)) {
			byte[] decoded = TOTPSecret.decode(secret);
			map.put("valid", totp.validate(decoded, code));
		} else {
			map.put("error", "No secret");
		}
		
		return map;
	}
	
	private int getMaxAge() {
		return ((60 * 60) * 24) * 7;
	}
	
	private Cookie createCookie(String username, String secret) {
		byte[] value = (username + SEPARATOR + secret).getBytes();
		
		Cookie cookie = new Cookie(COOKIE_NAME, new String(Base64.encodeBase64(value)));
		cookie.setMaxAge(getMaxAge());
		cookie.setPath("/");
		return cookie;
	}
	
	private Cookie destroyCookie(String username, String secret) {
		byte[] value = (username + SEPARATOR + secret).getBytes();
		
		Cookie cookie = new Cookie(COOKIE_NAME, new String(Base64.encodeBase64(value)));
		cookie.setMaxAge(0);
		cookie.setPath("/");
		return cookie;
	}
	
	private Cookie getCookie(HttpServletRequest request) {
		Cookie[] cookies = request.getCookies();
		if (cookies == null) return null;
		for (Cookie cookie : cookies) {
			if (COOKIE_NAME.equals(cookie.getName())) {
				return cookie;
			}
		}
		return null;
	}
	
	private String decodeCookie(Cookie cookie) {
		String value = cookie.getValue();
		return new String(Base64.decodeBase64(value));
	}
	
}
