package com.drive2code;

import java.util.Date;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * Contains methods for verifying and creating JSON web tokens.
 * @author chase
 */
public class JwtService {
	
	private final String secret;	
	
	
	/**
	 * Issued tokens expire in 3 hours
	 */
	private final long expiresIn = 10_800L * 1000L;
	
	public JwtService(String secret) {
		this.secret = secret;
	}
	
	/**
	 * Parses a JWT signed with a secret and returns the subject claim.
	 * 
	 * @param tokenString
	 * @return
	 */
	public String verifyToken(String tokenString) {		
		Jws<Claims> claims = Jwts.parser()
			.setSigningKey(secret.getBytes())
			.parseClaimsJws(tokenString); // this throws a number of exceptions
		
		return claims.getBody().getSubject();			
	}
	
	public String issueToken(String userId) {
		
		// calculate expiration time
		Date now = new Date();		
		Date expiration = new Date(now.getTime() + expiresIn);
		
		String jwt = Jwts.builder()
						.setSubject(userId)
						.setExpiration(expiration)
						.setHeaderParam("typ", "jwt")
						.signWith(SignatureAlgorithm.HS256, secret.getBytes())
						.compact();
		
		return jwt;
		
	}

}
