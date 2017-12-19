package com.drive2code.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@RunWith(JUnit4.class)
public class JwtAuthenticationProviderTest {
	
	private JwtAuthenticationProvider authProvider;
		
	@Before
	public void setUp() {
		authProvider = new JwtAuthenticationProvider(JwtTestUtils.secret);
	}

	@Test
	public void testSupports() {
		assertTrue(authProvider.supports(JwtAuthenticationToken.class));
		assertTrue(!authProvider.supports(UsernamePasswordAuthenticationToken.class));
	}
	
	@Test
	public void testAuthenticate() {
		JwtAuthenticationToken token = new JwtAuthenticationToken(JwtTestUtils.SIMPLE_TEST_JWT);
		Authentication fullyPopulatedToken = authProvider.authenticate(token);
		assertNotNull(fullyPopulatedToken);
		assertTrue(fullyPopulatedToken instanceof JwtAuthenticationToken);
		assertEquals(JwtTestUtils.TEST_SUBJECT, fullyPopulatedToken.getPrincipal());
		assertEquals(JwtTestUtils.TEST_SUBJECT, fullyPopulatedToken.getName());
	}
	
	@Test
	public void testAuthenticateWithScopes() {
		JwtAuthenticationToken token = new JwtAuthenticationToken(JwtTestUtils.TEST_JWT_WITH_SCOPES);
		Authentication fullyPopulatedToken = authProvider.authenticate(token);		
		assertEquals(JwtTestUtils.TEST_SUBJECT, fullyPopulatedToken.getPrincipal());
		assertEquals(JwtTestUtils.TEST_SUBJECT, fullyPopulatedToken.getName());
		assertEquals(2, fullyPopulatedToken.getAuthorities().size());
		assertTrue(fullyPopulatedToken.getAuthorities().contains(new SimpleGrantedAuthority("admin")));
		assertTrue(fullyPopulatedToken.getAuthorities().contains(new SimpleGrantedAuthority("user")));
	}
	
	@Test(expected=AuthenticationException.class)
	public void testAuthenticateShouldFail() {
		JwtAuthenticationToken token = new JwtAuthenticationToken(JwtTestUtils.TAMPERED_WITH_JWT);
		authProvider.authenticate(token);
	}
	
	@Test
	public void testAuthenticateWithBlankScopes() {
		JwtAuthenticationToken token = new JwtAuthenticationToken(JwtTestUtils.TEST_JWT_WITH_BLANK_SCOPES);
		Authentication fullyPopulatedToken = authProvider.authenticate(token);
		assertNotNull(fullyPopulatedToken.getAuthorities());
		assertEquals(0, fullyPopulatedToken.getAuthorities().size());
	}

}
