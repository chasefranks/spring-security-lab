package com.drive2code.security;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

@SuppressWarnings("serial") // TODO will we need serialization
public class JwtAuthenticationToken extends AbstractAuthenticationToken {
	
	private String credentials;
	private String principal;
	
	public JwtAuthenticationToken(String jwt) {
		super(null);
		this.credentials = jwt;
	}
	
	public JwtAuthenticationToken(String jwt, String principal) {
		super(null);
		this.credentials = jwt;
		this.principal = principal;
	}
	
	public JwtAuthenticationToken(String jwt, String principal, Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.credentials = jwt;
		this.principal = principal;
	}

	public JwtAuthenticationToken(Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
	}

	@Override
	public String getCredentials() {
		return this.credentials;
	}

	@Override
	public String getPrincipal() {
		return this.principal;
	}

}
