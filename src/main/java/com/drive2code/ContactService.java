package com.drive2code;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;

@Service
public class ContactService {
	
	// private implementation details
	private Map<Integer, Contact> contacts = new HashMap<>();
	private Random random = new Random();
	
	private Contact insertNewContact(Contact c) {
		
		int id;
		
		do {
			id = random.nextInt(50000);
		} while (contacts.containsKey(id));
		
		c.id = id;
		contacts.put(id, c);
		
		return c;
		
	}
	
	public boolean containsContact(int id) {
		return contacts.containsKey(id);
	}
	
	public Contact createContact(Contact c, String userId) {		
		c.userId = userId;
		return insertNewContact(c);		
	}
	
	public Contact updateContact(Contact c, String userId) {		
		if (containsContact(c.id)) {
			c.userId = userId;
			insertNewContact(c);
		}
		return contacts.get(c.id);		
	}
	
	public Contact getContact(int id) {
		return contacts.get(id);
	}
	
	public List<Contact> getContactsByUser(String userId) {
		return contacts.values().stream()
				.filter(c -> c.userId.equals(userId))
				.collect(Collectors.toList());
	}

	public void deleteContact(int id) {
		contacts.remove(id);		
	}
	
}
