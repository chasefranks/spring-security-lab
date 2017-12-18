package com.drive2code;

import java.util.Arrays;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.GrantedAuthoritiesContainer;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

@SpringBootApplication
public class SpringSecurityLabApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityLabApplication.class, args);
	}
	
	@Bean
	public PasswordEncoder bcryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public CommandLineRunner demoBcrypt(PasswordEncoder passwordEncoder) {
		return (args) -> {
			System.out.println("Password 'sara' bcrypted is: " + passwordEncoder.encode("sara"));
		};
	}
		
	/**
	 * Create in-memory user store with bcrypt encoded passwords. Normally, the
	 * plain password would be provided by the user when they are created and only the
	 * bcrypt encoded version would be saved. 
	 * 
	 * @return
	 */
	@Bean
	public UserDetailsService inMemoryUserDetails(PasswordEncoder passwordEncoder) {
				
		InMemoryUserDetailsManager inMemoryUserDetailsManager = new InMemoryUserDetailsManager();
		
		inMemoryUserDetailsManager.createUser(		
			User.withUsername("chase")
				.password(passwordEncoder.encode("chase"))
				.roles("USER", "ADMIN")
				.build()
		);
		
		inMemoryUserDetailsManager.createUser(
			User.withUsername("john")
				.password(passwordEncoder.encode("john"))
				.roles("USER")
				.build()
		);
		
		inMemoryUserDetailsManager.createUser(
			User.withUsername("sara")
				.password(passwordEncoder.encode("sara"))
				.roles("USER")
				.build()
		);
		
		return inMemoryUserDetailsManager;
		
	}
	
	/**
	 * Demo how an {@link AuthenticationProvider} makes the authentication decision.
	 * 
	 * @param authProvider
	 * @return
	 */
	@Bean
	public CommandLineRunner demoDaoAuthenticationProvider(AuthenticationProvider authProvider) {
		return (args) -> {
			System.out.println(authProvider.supports(UsernamePasswordAuthenticationToken.class));
			System.out.println(authProvider.supports(PreAuthenticatedAuthenticationToken.class));
			
			Authentication token = new UsernamePasswordAuthenticationToken("chase", "chase");
			System.out.println("is authenticated: " + token.isAuthenticated());
			
			Authentication fullyPopulatedToken = authProvider.authenticate(token);
			System.out.println("is authenticated: " + fullyPopulatedToken.isAuthenticated());
			
			if (token != fullyPopulatedToken) {
				System.out.println("new token issued");
			}
			
			fullyPopulatedToken.getAuthorities().forEach(grantedAuthority -> {
				System.out.println(grantedAuthority.getAuthority());
			});
			
			System.out.println(fullyPopulatedToken.getCredentials());
			
			SecurityContextHolder.getContext().setAuthentication(fullyPopulatedToken);
			
		};
	}
	
	/**
	 * Create a {@link DaoAuthenticationProvider} with our {@link PasswordEncoder} and 
	 * {@link UserDetailsService} for demo purposes.
	 * 
	 * @param userDetails
	 * @param passwordEncoder
	 * @return
	 */
	@Bean
	public AuthenticationProvider daoAuthenticationProvider(UserDetailsService userDetails, PasswordEncoder passwordEncoder) {
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
		authProvider.setPasswordEncoder(passwordEncoder);
		authProvider.setUserDetailsService(userDetails);
		return authProvider;		
	}
	
	@Bean
	public CommandLineRunner demoProviderManager(AuthenticationManager authManager) {
		return (args) -> {
			Authentication token = new UsernamePasswordAuthenticationToken("sara", "sara");
			Authentication fullyPopulatedToken = authManager.authenticate(token);
			
			if (fullyPopulatedToken.isAuthenticated()) {
				System.out.println(fullyPopulatedToken.getName() + " is authenticated with authorities: ");
				fullyPopulatedToken.getAuthorities().forEach(grantedAuthority -> {
					System.out.println(grantedAuthority.getAuthority());
				});
			} else {
				System.out.println(fullyPopulatedToken + " is not authenticated.");
			}
		};
	}
	
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationProvider authProvider) {
		AuthenticationManager authManager = new ProviderManager(Arrays.asList(authProvider));
		return authManager;		
	}
	
}
