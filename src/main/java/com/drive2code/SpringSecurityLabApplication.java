package com.drive2code;

import java.util.List;

import javax.servlet.Filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.UserDetailsManagerConfigurer.UserDetailsBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@SpringBootApplication
public class SpringSecurityLabApplication {
	
	private static final Logger log = LoggerFactory.getLogger(SpringSecurityLabApplication.class);

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityLabApplication.class, args);
	}
	
	/**
	 * A real {@link UserDetailsService} would connect to a database of users. Here we use an in-memory
	 * user details service to define our users.
	 * 
	 * @return
	 */
	@Bean 
	public UserDetailsService basicAuthUsers() {
		
		InMemoryUserDetailsManager userDetailsManager = new InMemoryUserDetailsManager();
		
		// define users here
		userDetailsManager.createUser(User.withUsername("chase").password("franks").roles("ADMIN").build());
		userDetailsManager.createUser(User.withUsername("austin").password("powers").roles("USER").build());
		userDetailsManager.createUser(User.withUsername("fat").password("bastard").roles("USER").build());
		userDetailsManager.createUser(User.withUsername("doctor").password("evil").roles("USER").build());
		
		return userDetailsManager;
		
	}
	
	@Bean
	public WebSecurityConfigurerAdapter jwtWebSecurityChain(JwtService jwtService) {
		return new WebSecurityConfigurerAdapter() {
			@Override
			protected void configure(HttpSecurity http) throws Exception {
				http.antMatcher("/api/**")
					.authorizeRequests().anyRequest().authenticated()
					.and()
					.addFilterAt(new JwtAuthFilter(jwtService), BasicAuthenticationFilter.class)
					.csrf().disable()
					.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
			}
		};
	}
	
	@Bean
	public JwtService jwtService(@Value("${jwt.secret}") String secret) {
		return new JwtService(secret);
	}
	
	/*
	 * the methods below are for debugging purposes only
	 */
	
	/**
	 * Retrieves the main {@link FilterChainProxy} bean from the {@link ApplicationContext}, and
	 * displays some useful information about the internal filter chains it holds.
	 * 
	 * @param ctx
	 * @return
	 */
	@Bean
	public CommandLineRunner inspectSpringSecurityFilterChain(ApplicationContext ctx) {
		return (args) -> {
			FilterChainProxy filterChain = (FilterChainProxy) ctx.getBean("springSecurityFilterChain");
			log.info("springSecurityFilterChain info:");
			log.info("number of filter chains: " + filterChain.getFilterChains().size());
			
			filterChain.getFilterChains().forEach(chain -> {
				displayFilterChainInfo(chain);
			});
						
		};
	}
	
	private void displayFilterChainInfo(SecurityFilterChain filterChain) {
		List<Filter> filters = filterChain.getFilters();
		log.info("chain: number of filters " + filters.size());
		filters.forEach(filter -> {
			log.info("filter type: " + filter.getClass().getName());
		});	
	}
	
}
