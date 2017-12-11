package com.drive2code;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AdminController {
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	@GetMapping("/api/admin/resource")
	public String getAdminResource() {
		return "admin resource";
	}
	
	/**
	 * Allow admin to retrieve user details.
	 * 
	 * @param username
	 * @return
	 */
	@GetMapping("/api/admin/user/{username}")
	public UserDetails getUserByUserName(@PathVariable String username) {
		return userDetailsService.loadUserByUsername(username);
	}
	
	/**
	 * Allow admin to update user role.
	 * 
	 * @param username
	 * @param role
	 * @return
	 */
	@PutMapping("/api/admin/user/{username}")
	public UserDetails updateUser(@PathVariable String username, @RequestBody final String role) {
		
		UserDetails found = userDetailsService.loadUserByUsername(username);
		
		if (found == null) {
			return found;
		}
		
		InMemoryUserDetailsManager inMemoryUserDetailsManager = (InMemoryUserDetailsManager) userDetailsService;
		
		GrantedAuthority newRole = new GrantedAuthority() {
			@Override
			public String getAuthority() {
				return "ROLE_" + role;
			}
		};
		
		if (found.getAuthorities().contains(newRole)) { // role is already there
			return found;
		} else {
			UserBuilder user = User.withUsername(found.getUsername());
			user.password(found.getPassword());
			user.roles(role);
			inMemoryUserDetailsManager.updateUser(user.build());	
		}		
			
		return inMemoryUserDetailsManager.loadUserByUsername(username);
		
	}
}
