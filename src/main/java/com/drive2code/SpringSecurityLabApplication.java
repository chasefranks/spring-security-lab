package com.drive2code;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

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
	
}
