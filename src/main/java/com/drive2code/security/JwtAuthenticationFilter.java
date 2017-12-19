package com.drive2code.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

public class JwtAuthenticationFilter extends OncePerRequestFilter {
	
	private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
	
	private AuthenticationManager authenticationManager;	

	public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		String authHeader = request.getHeader("Authorization");
		
		if (!hasBearerToken(authHeader)) {
			filterChain.doFilter(request, response);
			return;
		}
		
		log.debug("Authorization header contains Bearer token");
		String jwt = parseJwtFromHeader(authHeader);
		
		/*
		 * check if a previous filter hasn't already authenticated this user
		 */
		Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();
		
		if (currentAuth == null || currentAuth.isAuthenticated()) {
			JwtAuthenticationToken token = new JwtAuthenticationToken(jwt);
			Authentication authResult = authenticationManager.authenticate(token);
			
			log.debug("authentication success: " + authResult);
			
			SecurityContextHolder.getContext().setAuthentication(authResult);
		}
		filterChain.doFilter(request, response);
		
	}

	private String parseJwtFromHeader(String authHeader) {
		String[] tokens = authHeader.trim().split(" ");		
		return tokens[1];
	}

	private boolean hasBearerToken(String authHeader) {
		if (authHeader == null || authHeader.length() == 0)
			return false;
		
		return authHeader.startsWith("Bearer");
	}
	
}
