package com.drive2code;

import java.util.List;

import javax.servlet.Filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;

@SpringBootApplication
public class SpringSecurityLabApplication {
	
	private static final Logger log = LoggerFactory.getLogger(SpringSecurityLabApplication.class);

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityLabApplication.class, args);
	}
	
	@Bean
	public WebSecurityConfigurerAdapter adminWebSecurity() {
		return new WebSecurityConfigurerAdapter() {
			@Override
			protected void configure(HttpSecurity http) throws Exception {				
				http.authorizeRequests()
					.antMatchers("/api/admin/**")
					.hasRole("ADMIN")
					.and()
					.httpBasic()
					.and()
					.csrf().disable()
					.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS);  
				
			}
		};		
	}
	
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
	
	/**
	 * Retrieves the {@link AuthenticationManager} from {@link ApplicationContext} and shows how it is used
	 * to make the authentication decision.
	 * 
	 * @param ctx
	 * @return
	 */
	@Bean
	public CommandLineRunner inspectAuthenticationManager(ApplicationContext ctx) {
		return (args) -> {
			AuthenticationManager authManager = (AuthenticationManager) ctx.getBean(AuthenticationManager.class);
			Authentication authentication = authManager.authenticate(new UsernamePasswordAuthenticationToken("chase", "changeme"));
			
			log.info("authentication success!");
			log.info(authentication.getName());
			log.info(Boolean.toString(authentication.isAuthenticated()));
			
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
