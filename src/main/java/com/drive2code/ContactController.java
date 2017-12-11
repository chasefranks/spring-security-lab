package com.drive2code;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/contact")
public class ContactController {
	@GetMapping("/{id}")
	public Contact getContact(@PathVariable String id) {
		Contact c = new Contact();
		c.id = id;
		c.userId = "chase";
		c.name = "john doe";
		c.email = "johndoe@example.com";
		return c;
	}
}
