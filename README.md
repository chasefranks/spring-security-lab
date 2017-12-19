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

### Step 1. Creating Our `UserDetailsService`

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

### Step 2. Creating an `AuthenticationProvider`

The key Spring construct for performing authentication is the `AuthenticationManager`, which is an interface with one method

```java
Authentication authenticate(Authentication authentication) throws AuthenticationException;
```

The `Authentication` object passed to this method is also an interface which extends the fundamental `java.security.Principal` interface:

```java
public interface Authentication extends Principal, Serializable {	
	Collection<? extends GrantedAuthority> getAuthorities();
	Object getCredentials();
	Object getDetails();
	Object getPrincipal();
	boolean isAuthenticated();
	void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException;
}
```

The credentials inside of the `Authentication` token prove the user is who they say they are. In our example above, `getCredentials()` would return the password "sara". The principal is who they are claiming to be, so `getPrincipal()` would return the user name "sara". To perform authentication, the following steps would be performed:

1. A partially populated `Authentication` token would be formed. At this stage you know nothing about the user except the principal they are claiming to be and some credentials they have passed along, so the partial credentials might look like ```new UsernamePasswordAuthenticationToken("chase", "chase")```.

2. The authentication token would be passed to the `AuthenticationManager`s authenticate method.

3. The `AuthenticationManager` would look up the user in a database, compare bcrypted passwords, and if they match, return a fully populated authentication token, including any roles or authorities the user might have (returned by the `getAuthorities()` method). Since tokens are meant to be immutable, most implementations of `AuthenticationManager` would probably create a new `Authentication` token and return it from the `authenticate()` method.

4. If there was a problem during authentication, like the passwords not matching, the responsibility of the `AuthenticationManager` is to throw an `AuthenticationException`.

You can write your own `AuthenticationManager` by implementing the interface, and passing it your custom `Authentication` token and authentication logic. It may help to see one in action first however. 

The most commonly used authentication manager implementation is the `ProviderManager` which performs authentication by delegating to an internal list of `AuthenticationProvider` instances.

```java
public interface AuthenticationProvider {	
	Authentication authenticate(Authentication authentication) throws AuthenticationException;
	boolean supports(Class<?> authentication);
}
```

When the `ProviderManager`s `authenticate(token)` method is called, it iterates through each provider in its list and calls `supports(token.class)` to see if the provider can handle that type of token. For example, the `DaoAuthenticationProvider` supports the `UsernamePasswordAuthenticationToken`, so

```java
authProvider.supports(UsernamePasswordAuthenticationToken.class))
```

would return true. If the provider supports the token type, the provider manager delegates to the provider's `authenticate()` method.

To see how this all works, let's create a `DaoAuthenticationProvider`

```java
@Bean
public AuthenticationProvider daoAuthenticationProvider(UserDetailsService userDetails, PasswordEncoder passwordEncoder) {
	DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
	authProvider.setPasswordEncoder(passwordEncoder);
	authProvider.setUserDetailsService(userDetails);
	return authProvider;		
}
```

Since the provider actually makes the authentication decision, it needs to be able to look up users and apply bcrypt password encoding. Hence we have injected those into our `@Bean` method as dependencies and pass those to the provider via setters.

Let's see how authentication is performed at the provider level. First, we create a token that is supported by the `DaoAuthenticationProvider`:

```java
Authentication token = new UsernamePasswordAuthenticationToken("chase", "chase");
```

The principal is simply the user name "chase" as a String. The credentials argument is the password "chase", again passed as a String. 

Then to authenticate, we simply call the provider's authenticate method

```java
Authentication fullyPopulatedToken = authProvider.authenticate(token);
```

and capture the fully populated token as the return value.

It's that easy. The `ProviderManager` iterates through a list of objects like `DaoAuthenticationProvider` until it hits one that can support the token passed in, then it calls `authenticate(token)` just like we've done above. A client relying on the `ProviderManager` could then decide to set the token in the current `SecurityContext`

```java
SecurityContextHolder.getContext().setAuthentication(fullyPopulatedToken);
```

and from this point on, the user is considered authenticated in the app and can do whatever they are allowed.

### Step 3. Creating a `ProviderManager`

We have everything we need now to create an `AuthenticationManager`, in this case an instance of `ProviderManager`. Since `ProviderManager` depends on a list of `AuthenticationProvider`s, we can create it using the corresponding constructor, wiring in our single `DaoAuthenticationProvider` created earlier:

```java
@Bean
public AuthenticationManager authenticationManager(AuthenticationProvider authProvider) {
	AuthenticationManager authManager = new ProviderManager(Arrays.asList(authProvider));
	return authManager;		
}
```

Finally, we demo it in a `@CommandLineRunner` just as before

```java
demoProviderManager(AuthenticationManager authManager) {
	Authentication token = new UsernamePasswordAuthenticationToken("sara", "sara");
	Authentication fullyPopulatedToken = authManager.authenticate(token);
}
```

### Step 4. Use It

Let's put everything we've done so far together and see it in action. 

#### Web Security 

First let's test web security by using Spring Boot to create a protected route. By default, the url pattern `/**` is protected which matches all urls. Let's narrow this down to the pattern `/secure/**` by adding this line to the application.properties file

````
security.basic.path=/secure/**
```

Now add this `@RestController` as a static member of our application bootstrap class

```java
@RestController
@RequestMapping("/secure")
public static class secureResource {
	@GetMapping
	public String getSecure() {
		return "you're in!";
	}
}
```

Test it with curl

```
curl localhost:8080/secure
{"timestamp":1513688638195,"status":401,"error":"Unauthorized","message":"Full authentication is required to access this resource","path":"/secure"}

curl -u sara:sara localhost:8080/secure
you're in!
```

There's another way we can test our secure configuration.

#### Method Security

Web security is only one side of Spring Security. You might imagine a console application that prompts a user for their user name and password, and then performs some secure work. This takes us back to the realm of basic Java objects and their methods. Since a method is the fundamental unit of execution in Java, you may wonder how we can simply secure a method invocation.

To secure a method in Spring, simply apply the `@Secure` annotation. For example, let's say we want to provide a way for an admin to retrieve their password. Let's create simple Java class that returns the password:

```java
@Component
public class AdminPasswordService {
	@Secured({"ROLE_ADMIN"})
	public String getPassword() {
		return "chase";
	}
}
```

Any thread invoking this method has to have in its `SecurityContext` an authenticated principal with the authority `ROLE_ADMIN`. For example, if we just try to call the method from a `CommandLineRunner`

```
@Bean
public CommandLineRunner demoMethodSecurity(AdminPasswordService adminPasswordService, AuthenticationManager authManager) {
	return (args) -> {						
		// attempt secure method call
		System.out.println("admin password is: " + adminPasswordService.getPassword());
	};
}
```

the `main` thread would need to call

```java
SecurityContextHolder.getContext().setAuthentication(token);
```

before our invocation of the secure method `adminPasswordService.getPassword()`. So let's prompt the user for their user name and password beforehand. Since `CommandLineRunners` are run in the order they are declared, let's define one to log the user in before we attempt to invoke the secure method. Place this code before the `demoMethodSecurity` method above:

```java
@Bean 
public CommandLineRunner consoleLogin(AuthenticationManager authManager) {
	return (args) -> {						
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));			
		System.out.println("User name:");
		String userName = in.readLine();
		
		System.out.println("Enter password:");
		String password = in.readLine();
		
		in.close();
		
		System.out.println("Authenticating user: " + userName + " with supplied password");
		Authentication token = authManager.authenticate(new UsernamePasswordAuthenticationToken(userName, password));
		
		System.out.println("Authentication successful");
		SecurityContextHolder.getContext().setAuthentication(token);
		
	};
}
```

Now try running it by logging in with the identity of the different users we defined in [Step 1](#step-1-creating-our-userdetailsservice). You should only be able to get the admin password with the admin user.

**Challenge:** Let's expand on our demo a little. Changing our example above, allow a single admin user to change their password on start up.

Hint: You can use `SecurityContextHolder.getContext().getAuthentication()` to get the currently logged in user's token inside of the `@Secured` method. Then look at the `InMemoryUserDetailsManager` docs and the available methods to figure out how to change the user's password.

## References

[Spring Method Security](https://docs.spring.io/spring-security/site/docs/5.0.0.RELEASE/reference/htmlsingle/#jc-method)







