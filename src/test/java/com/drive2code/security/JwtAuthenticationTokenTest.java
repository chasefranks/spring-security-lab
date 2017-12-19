package com.drive2code.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.drive2code.security.JwtAuthenticationToken;

@RunWith(JUnit4.class)
public class JwtAuthenticationTokenTest {
	
	private static final String TEST_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";

	@Test
	public void testPreAuthConstructor() {
		JwtAuthenticationToken preAuthtoken = new JwtAuthenticationToken(TEST_JWT);
		assertNotNull(preAuthtoken);
		assertEquals(TEST_JWT, preAuthtoken.getCredentials());
		assertTrue(preAuthtoken.getPrincipal() == null);
		assertEquals(AuthorityUtils.NO_AUTHORITIES, preAuthtoken.getAuthorities());
	}
	
	@Test
	public void testPostAuthConstructor() {
		JwtAuthenticationToken postAuthToken = new JwtAuthenticationToken(TEST_JWT, "1234567890");
		assertNotNull(postAuthToken);
		assertEquals(TEST_JWT, postAuthToken.getCredentials());
		assertEquals("1234567890", postAuthToken.getPrincipal());
		assertEquals(AuthorityUtils.NO_AUTHORITIES, postAuthToken.getAuthorities());
	}
	
	@Test
	public void testPostAuthConstructorWithAuthorities() {
		JwtAuthenticationToken postAuthToken = new JwtAuthenticationToken(TEST_JWT, "1234567890", Arrays.asList(new SimpleGrantedAuthority("admin")));
		assertNotNull(postAuthToken);
		assertEquals(TEST_JWT, postAuthToken.getCredentials());
		assertEquals("1234567890", postAuthToken.getPrincipal());
		assertTrue(postAuthToken.getAuthorities().contains(new SimpleGrantedAuthority("admin")));
	}

}
