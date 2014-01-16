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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class MainController {

	private TOTP totp;
	
	@Autowired
	public void setTotp(TOTP totp) {
		this.totp = totp;
	}

	@RequestMapping (value = {"/", ""})
	public String index(Model model, HttpServletRequest request) {
		Cookie secret = getCookie("secret", request);
		Cookie username = getCookie("username", request);
		String url = request.getRequestURL().toString();
		if (url.endsWith("/")) {
			url = url.substring(0, url.length() - 1);
		}
		model.addAttribute("request", url);
		
		if (secret != null && username != null) {
			DateFormat format = DateFormat.getDateTimeInstance(DateFormat.FULL, DateFormat.FULL);
			Calendar instance = Calendar.getInstance();
			instance.add(Calendar.SECOND, secret.getMaxAge());
			
			String host = request.getServerName();
			model.addAttribute("secret", secret.getValue());
			model.addAttribute("host", host);
			model.addAttribute("username", username.getValue());
			model.addAttribute("validUntil", -1);
			model.addAttribute("qr", GoogleAuthenticator.getQRUrl(username.getValue(), host, secret.getValue()));
		}
		
		return "index";
	}
	
	@RequestMapping (value = "/totp/generate", produces = "application/json")
	@ResponseBody
	public Object generate(@RequestParam (value="username", required = false) String username, HttpServletRequest request, HttpServletResponse response) {
		if (!StringUtils.hasText(username)) {
			return Collections.singletonMap("error", "Username missing!");
		}
		
		byte[] key = TOTPSecret.generate();
		
		String secret = TOTPSecret.encode(key);
		String host = request.getServerName();
		String qr = GoogleAuthenticator.getQRUrl(username, host, secret);
		
		response.addCookie(createCookie("secret", secret));
		response.addCookie(createCookie("username", username));
		
		Map<String,Object> map = new HashMap<String, Object>();
		map.put("username", username);
		map.put("host", host);
		map.put("secret", secret);
		map.put("qr", qr);
		return map;
	}
	
	@RequestMapping (value = "/totp/refresh", produces = "application/json")
	public @ResponseBody Object refresh(HttpServletRequest request, HttpServletResponse response) {
		Cookie cookie = getCookie("secret", request);
		Map<String,Object> map = new HashMap<String, Object>();

		if (cookie != null) {
			cookie.setMaxAge(getMaxAge());
			cookie.setPath("/");
			response.addCookie(cookie);
			
			Cookie user = getCookie("username", request);
			user.setMaxAge(getMaxAge());
			response.addCookie(user);
		} else {
			map.put("error", "No secret");
		}
		
		map.put("refreshed", cookie != null);
		return map;
	}
	
	@RequestMapping (value = "/totp/destroy", produces = "application/json")
	@ResponseBody
	public Object destroy(HttpServletRequest request, HttpServletResponse response) {
		Cookie cookie = getCookie("secret", request);
		Map<String,Object> map = new HashMap<String, Object>();

		if (cookie != null) {
			cookie.setValue(null);
			cookie.setMaxAge(0);
			cookie.setPath("/");
			response.addCookie(cookie);
		} else {
			map.put("error", "No secret");
		}
		
		map.put("destroyed", cookie != null);
		return map;
	}
	
	@RequestMapping (value = "/totp/verify", produces = "application/json")
	@ResponseBody
	public Object verify(@RequestParam (value="code", required = false) Integer code, HttpServletRequest request) {
		if (code == null) {
			return Collections.singletonMap("error", "Code missing!");
		}
		
		Cookie cookie = getCookie("secret", request);
		Map<String,Object> map = new HashMap<String, Object>();
		
		if (cookie != null) {
			byte[] secret = TOTPSecret.decode(cookie.getValue());
			boolean valid = totp.validate(secret, code);
			map.put("valid", valid);
		} else {
			map.put("valid", false);
			map.put("error", "No secret");
		}
		
		return map;
	}
	
	private int getMaxAge() {
		return ((60 * 60) * 24) * 7;
	}
	
	private Cookie createCookie(String name, String secret) {
		Cookie cookie = new Cookie(name, secret);
		cookie.setMaxAge(getMaxAge());
		cookie.setPath("/");
		return cookie;
	}
	
	private Cookie getCookie(String name, HttpServletRequest request) {
		Cookie[] cookies = request.getCookies();
		if (cookies == null) return null;
		for (Cookie cookie : cookies) {
			if (name.equals(cookie.getName())) {
				return cookie;
			}
		}
		return null;
	}
	
	
}
