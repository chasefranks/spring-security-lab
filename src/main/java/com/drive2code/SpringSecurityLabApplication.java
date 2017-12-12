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
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@SpringBootApplication
public class SpringSecurityLabApplication {
	
	private static final Logger log = LoggerFactory.getLogger(SpringSecurityLabApplication.class);

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityLabApplication.class, args);
	}
	
	@Bean
	public WebSecurityConfigurerAdapter jwtWebSecurityChain() {
		return new WebSecurityConfigurerAdapter() {
			@Override
			protected void configure(HttpSecurity http) throws Exception {
				http.antMatcher("/api/**")
					.authorizeRequests().anyRequest().authenticated()
					.and()
					.addFilterAt(new JwtAuthFilter(), BasicAuthenticationFilter.class)
					.csrf().disable();
			}
		};
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
