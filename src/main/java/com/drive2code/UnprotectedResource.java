package com.drive2code;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/unprotected")
public class UnprotectedResource {	
	@GetMapping
	public String getUnprotectedResource() {
		return "unprotected";
	}
}
