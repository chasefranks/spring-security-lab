package com.drive2code;

import java.io.IOException;
import java.security.Principal;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

public class JwtAuthFilter extends GenericFilterBean {
	
	private static final Logger log = LoggerFactory.getLogger(JwtAuthFilter.class);
	
	private JwtService jwtService;	

	public JwtAuthFilter(JwtService jwtService) {
		this.jwtService = jwtService;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		log.info("request received");
		log.info("checking for bearer token in Authorization header");
		
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		
		String authHeaderValue = httpRequest.getHeader("Authorization");
		
		if (authHeaderValue == null) {
			log.info("no Authorization Header");
			log.info("requests should have jwt token in form - Authorization: Bearer <jwt>");
			chain.doFilter(request, response);
		}
		
		log.info("Authorization header present: " + authHeaderValue);
		
		// extract token from authHeaderValue and use jjwt library to verify
		String tokenString = authHeaderValue.trim().split(" ")[1];
		log.info("token: " + tokenString);
		
		String subject = jwtService.verifyToken(tokenString);
		
		log.info("jwt verified: subject = {}", subject);
		
		// use this logic to populate the SecurityContext if the jwt is valid		
		Principal p = new Principal() {			
			@Override
			public String getName() {
				return subject;
			}
		};
		
		Authentication auth = new UsernamePasswordAuthenticationToken(p, null, null);
		
		log.info("adding authentication {} to the SecurityContext", auth);
		SecurityContextHolder.getContext().setAuthentication(auth);
		
		// send request down the chain
		chain.doFilter(request, response);
		
	}

}
