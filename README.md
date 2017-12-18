# Spring Security Lab

A lab environment for experiments with Spring Security.

## Usage

Use `git checkout master` to reset this project back to the defaults and start a new lab. From here, create a new branch for your experiment and name it something appropriate like

```
git checkout -b jwt-lab
```

Add documentation to this README when your lab is complete.

## Lab - Authentication Manager

In this lab, we'll set up an `AuthenticationManager` and walk through how the process of how it authenticates a user. We'll focus on the most commonly used type of `AuthenticationManager` called a `ProviderManager`. Our goal is to have a fully functional `ProviderManager` backed by an in-memory user details service, and to step through the log in process in a debugger. In my opinion the best way to learn about Spring Security, to see the code in action. Spring Security follows the same pattern for authenticating for almost every method, so we gain a lot by simply understanding how a user logs in with a password.

Let's get to it!

### Step 1. Creating Our UserDetailsService

We first create a `UserDetailsService` that simulates a database of users.

```java
@Bean
public UserDetailsService inMemoryUserDetails() {
	
	BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
	
	InMemoryUserDetailsManager inMemoryUserDetailsManager = new InMemoryUserDetailsManager();
	
	inMemoryUserDetailsManager.createUser(		
		User.withUsername("chase")
			.password(passwordEncoder.encode("chase"))
			.roles("USER", "ADMIN")
			.build()
	);
	
	inMemoryUserDetailsManager.createUser(
		User.withUsername("john")
			.password(passwordEncoder.encode("john"))
			.roles("USER")
			.build()
	);
	
	inMemoryUserDetailsManager.createUser(
		User.withUsername("sara")
			.password(passwordEncoder.encode("sara"))
			.roles("USER")
			.build()
	);
	
	return inMemoryUserDetailsManager;
	
}
```

The `InMemoryUserDetailsManager` we use is backed by a `Map` instead of a database. Notice that we use a `PasswordEncoder`, namely the `BCryptPasswordEncoder`, to store the user names by bcrypt hash instead of the plain password. 

The key thing to know about bcrypt is that it is impossible to determine the original password from the bcrypt hash. For example the bcrypted version of the password sara is

```
$2a$10$CSeyyERfVj77N1/LhLq4t.UR7DIdhVyTtQ4JPZGuQpk09gcUGyEha
```

and it is impossible to recover sara from this string of gibberish. We would store the bcrypt version in the database when the user is created and forget the password sara forever by securely wiping it from memory. When the user logs in with the password sara, the password would be sent securely over HTTPS, and when it arrives to our app, we would apply the bcrypt encoder to it and compare it to the bcrypted version of the password from the database. If they match, the user is authenticated.
