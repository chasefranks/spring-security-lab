package com.drive2code;

import java.security.Principal;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/contact")
public class ContactController {
	
	private ContactService contactService;	
	
	@Autowired
	public ContactController(ContactService contactService) {
		this.contactService = contactService;
	}
	
	@PostMapping
	public Contact createContact(@RequestBody Contact c, Principal p) {
		return contactService.createContact(c, p.getName());
	}
	
	@GetMapping
	public List<Integer> getContacts(Principal p) {
		return contactService.getContactsByUser(p.getName()).stream()
				.map(c -> c.id)
				.collect(Collectors.toList());
	}

	@GetMapping("/{id}")
	public ResponseEntity<Object> getContact(@PathVariable int id, Principal principal) {
		
		Contact found = contactService.getContact(id);
		
		if (found == null) {
			return new ResponseEntity<>(HttpStatus.NOT_FOUND);
		}
		
		if (found.userId != null && !found.userId.equals(principal.getName())) {
			// principal doesn't own resource
			return new ResponseEntity<>("can't access this contact", HttpStatus.FORBIDDEN);
		}
		
		return new ResponseEntity(found, HttpStatus.OK);	
		
	}
	
	@DeleteMapping("/{id}")
	public ResponseEntity<Object> deleteContact(@PathVariable int id, Principal principal) {
		
		Contact found = contactService.getContact(id);
		
		if (found == null) {
			return new ResponseEntity<>(HttpStatus.NOT_FOUND);
		}
		
		if (found.userId != null && !found.userId.equals(principal.getName())) {
			// principal doesn't own resource
			return new ResponseEntity<>(HttpStatus.FORBIDDEN);
		}
		
		contactService.deleteContact(id);
		return new ResponseEntity<Object>("contact with id " + id + " deleted", HttpStatus.OK);
	}
}
