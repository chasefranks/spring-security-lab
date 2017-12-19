package com.drive2code.security;

public class JwtTestUtils {
	public static final String TEST_SUBJECT = "1234567890";
	public static final byte[] secret = "secret".getBytes();
	
	/*
	 * some jwts for testing
	 */
	
	/**
	 * a basic jwt signed with secret="secret"
	 */
	public static final String SIMPLE_TEST_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
	
	/**
	 * same basic jwt with scopes = "user admin"
	 */
	public static final String TEST_JWT_WITH_SCOPES = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwic2NvcGVzIjoidXNlciBhZG1pbiJ9.FG8ymcgUlDjHYQWmm8Sq5RgWWjl1_vLH4bj70WL4KH0";
	
	/**
	 * a tampered with version of SIMPLE_TEST_JWT, claims a different subject but with same signature
	 */
	public static final String TAMPERED_WITH_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwMSIsIm5hbWUiOiJKb2huIERvZSIsInNjb3BlcyI6InVzZXIgYWRtaW4ifQ.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
	
	/**
	 * basic jwt with scopes = " "
	 */
	public static final String TEST_JWT_WITH_BLANK_SCOPES = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwMSIsIm5hbWUiOiJKb2huIERvZSIsInNjb3BlcyI6IiAifQ.gD2kF-zJUEDtSQvF8grEL4Q1N3WCTF2YQU3Ql-MfoRs";
}
