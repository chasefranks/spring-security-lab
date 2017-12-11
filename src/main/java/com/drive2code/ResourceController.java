package com.drive2code;

import java.security.Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {
	
	private static final Logger log = LoggerFactory.getLogger(ResourceController.class);
	
	@GetMapping("/api/resource")
	public String getResource(Principal principal) {
		// authenticated Principal is injected into the method
		log.info("principal: " + principal.getName());
		return "resource";
	}

}
