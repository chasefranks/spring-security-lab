package com.drive2code.security;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public final class JwtAuthenticationToken extends AbstractAuthenticationToken {
	
	private static final long serialVersionUID = 804145243156880590L;
	
	private final String credentials;
	private final String principal;
	
	public JwtAuthenticationToken(String jwt) {
		super(null);
		this.credentials = jwt;
		this.principal = null;
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
		this.credentials = null;
		this.principal = null;
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
