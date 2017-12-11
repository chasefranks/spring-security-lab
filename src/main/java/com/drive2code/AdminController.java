package com.drive2code;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AdminController {
	@GetMapping("/api/admin/resource")
	public String getAdminResource() {
		return "admin resource";
	}
}
