package com.drive2code;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;

/**
 * Contains methods for verifying and creating JSON web tokens.
 * @author chase
 */
public class JwtService {
	
	private final String secret;	
	
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

}
