package com.drive2code.security;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;

public class JwtAuthenticationProvider implements AuthenticationProvider {
	
	private byte[] key;

	public JwtAuthenticationProvider(byte[] key) {
		this.key = key;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		
		JwtAuthenticationToken jwtToken = (JwtAuthenticationToken) authentication;
		
		try {
			Jws<Claims> claims = verifyToken(jwtToken.getCredentials());			
			return populateTokenFromClaims(jwtToken.getCredentials(), claims);			
		} catch (Exception e) {
			// TODO map unchecked exceptions from JJWT library to AuthenticationException with cause
			throw new BadCredentialsException("jwt not valid", e);
		}
		
	}

	/**
	 * Parses the {@link Jws} object returned by the JJWT library into a fully populated
	 * token.
	 * 
	 * If the jwt includes a <i>scopes</i> claim with value equal to a space delimited list of
	 * Spring roles, those will be parsed and used to populate the authorities in the returned
	 * {@link Authentication} token.
	 * 
	 * @param token the original base64 encoded jwt
	 * @param claims the {@link Jws} returned from signature verification
	 * @return a fully populated {@link JwtAuthenticationToken}
	 */
	JwtAuthenticationToken populateTokenFromClaims(String token, Jws<Claims> claims) {
		
		String subject = claims.getBody().getSubject();
		
		// accepts scopes claim with list of space-delimited roles
		if (claims.getBody().get("scopes", String.class) != null) {			
			Collection<GrantedAuthority> roles = new HashSet<>();
			
			String scopes = claims.getBody().get("scopes", String.class);			
			String[] scopeArray = scopes.trim().split(" ");
			
			for(String scope : scopeArray) {
				if (scope.length() > 0) {
					roles.add(new SimpleGrantedAuthority(scope));
				}
			}
			
			return new JwtAuthenticationToken(token, subject, Collections.unmodifiableCollection(roles));			
		} else {
			return new JwtAuthenticationToken(token, subject);
		}
			
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return JwtAuthenticationToken.class.isAssignableFrom(authentication);
	}
	
	/**
	 * Verifies the jwt passed in as a {@link String} and returns an {@link Jws} object
	 * that can be used to retrieve the claims.
	 * 
	 * @param token
	 * @return a {@link Jws} object holding the claims
	 */
	Jws<Claims> verifyToken(String token) {		
		Jws<Claims> claims = Jwts.parser()
			.setSigningKey(this.key)
			.parseClaimsJws(token);
		
		return claims;			
	}

}
