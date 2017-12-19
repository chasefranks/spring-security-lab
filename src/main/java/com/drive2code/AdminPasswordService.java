package com.drive2code;

import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Component;

@Component
public class AdminPasswordService {
	@Secured({"ROLE_ADMIN"})
	public String getPassword() {
		return "chase";
	}
}
