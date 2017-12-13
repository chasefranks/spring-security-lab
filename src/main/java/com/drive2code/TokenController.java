package com.drive2code;

import java.security.Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/token")
public class TokenController {
	
	private static final Logger log = LoggerFactory.getLogger(TokenController.class);
	
	private JwtService jwtService;

	@Autowired
	public TokenController(JwtService jwtService) {
		this.jwtService = jwtService;
	}
	
	@GetMapping
	public String getToken(Principal p) {
		log.info("request for token for user {} received", p.getName());
		return jwtService.issueToken(p.getName());
	}
}
