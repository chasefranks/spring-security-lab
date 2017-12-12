# Spring Security Lab

A lab environment for experiments with Spring Security.

## Usage

Use `git checkout master` to reset this project back to the defaults and start a new lab. From here, create a new branch for your experiment and name it something appropriate like

```
git checkout -b jwt-lab
```

## Lab: JSON Web Token (JWT)

In this lab, we will expose an end point `/token` that is protected with HTTP basic authentication and issues a jwt with the user name as the subject claim if the user successfully authenticates. This will be our login entry point. Then we will expose an API under `/api` and protect the url pattern `/api/**` with a stateless filter that performs the following check:

1. If the header `Authentication: Bearer <jwt>` is not present, reject the request.
2. Otherwise, extract the token, verify it, and populate the `SecurityContextHolder` with an authenticated principal using nothing but the verified token.

Once this is done, we will add a scope claim to the JWT that maps to roles in our Spring Security configuration. We will change the `/token` end point to recover the roles from the `UserDetailsService` and add them to the issued jwt as a scope claim. We will then change the JWT filter to populate the roles for the authenticated principal on every new request.

With that out of the way, let's get to work!

### The Problem Domain

We really need something a little more interesting to give us some context, so let's design a small REST API that manages contacts for the users of our application.

Let's start by defining a POJO (plain old Java object) to hold data for a single contact:

```java
public class Contact {
	public String id; // an id to reference a contact
	public String userId; // the id of the user
	
	public String name; // contact details
	public String phoneNumber;
	public String email;
}
```

Let's define a single REST route `/api/contact/{id}` that just makes up a contact with whatever id we pass in

```java
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
```

Now let's start it up. Remember that the Spring Boot security default has a single user with password logged to the console. Also, every url is secured with HTTP basic authentication by default. Let's grab the password from the console:

```
Using default security password: 94626ad2-e4e6-48f5-9f7b-fdd54c2b2329
```

and  make a request...

```
curl -u user:94626ad2-e4e6-48f5-9f7b-fdd54c2b2329 localhost:8080/api/contact/5 | jsonlint
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    94    0    94    0     0  11097      0 --:--:-- --:--:-- --:--:-- 11750
{
  "id": "5",
  "userId": "chase",
  "name": "john doe",
  "phoneNumber": null,
  "email": "johndoe@example.com"
}
```

Now let's set up our jwt filter.

## Writing Our Own Security Filter

We will first write a basic filter by extending `GenericFilterBean` and performs our basic jwt parsing and verification logic, and sets the authenticated `Principal`. Then following the usual pattern, we will write a filter chain that matches on `/api/**` and add our custom jwt filter to it. The trick will be in deciding where in the default Spring Security filter chain our filter should go.

First, let's configure a filter chain against the url pattern `/api/**`. Add this `@Bean` method to our bootstrap class

```
@Bean
public WebSecurityConfigurerAdapter jwtWebSecurityChain() {
	return new WebSecurityConfigurerAdapter() {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.antMatcher("/api/**")
				.authorizeRequests().anyRequest().authenticated()
				.and()
				.csrf().disable();
		}
	};
}
```

The fluent builder interface offered by the `HttpSecurity` object is a little subtle in my opinion, but remember the main idea? The `FilterChainProxy` holds a table of `SecurityFilterChain`s and each `SecurityFilterChain` applies a chain of filters in succession which perform various security roles. Usually, one of these filters performs authentication from the `ServletRequest` and as a result populates the `SecurityContext` with an `Authentication` token. The goal, whether using Java config by extending the `WebSecurityAdapter` class or using xml config, is the same: to configure this list of filter chains and the urls they match on.

So let's bounce the server and check the logs to make sure a new chain was added:

```
2017-12-12 05:08:49.001  INFO 28394 --- [           main] o.s.s.web.DefaultSecurityFilterChain     : Creating filter chain: OrRequestMatcher [requestMatchers=[Ant [pattern='/css/**'], Ant [pattern='/js/**'], Ant [pattern='/images/**'], Ant [pattern='/webjars/**'], Ant [pattern='/**/favicon.ico'], Ant [pattern='/error']]], []
2017-12-12 05:08:49.036  INFO 28394 --- [           main] o.s.s.web.DefaultSecurityFilterChain     : Creating filter chain: Ant [pattern='/api/**'], [org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter@720653c2, org.springframework.security.web.context.SecurityContextPersistenceFilter@41e1455d, org.springframework.security.web.header.HeaderWriterFilter@5c41d037, org.springframework.security.web.authentication.logout.LogoutFilter@736ac09a, org.springframework.security.web.savedrequest.RequestCacheAwareFilter@5eccd3b9, org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter@41477a6d, org.springframework.security.web.authentication.AnonymousAuthenticationFilter@45f24169, org.springframework.security.web.session.SessionManagementFilter@3eb631b8, org.springframework.security.web.access.ExceptionTranslationFilter@577f9109, org.springframework.security.web.access.intercept.FilterSecurityInterceptor@77128dab]
2017-12-12 05:08:49.042  INFO 28394 --- [           main] o.s.s.web.DefaultSecurityFilterChain     : Creating filter chain: OrRequestMatcher [requestMatchers=[Ant [pattern='/token']]], [org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter@4905c46b, org.springframework.security.web.context.SecurityContextPersistenceFilter@2d7e1102, org.springframework.security.web.header.HeaderWriterFilter@466d49f0, org.springframework.security.web.authentication.logout.LogoutFilter@72458efc, org.springframework.security.web.authentication.www.BasicAuthenticationFilter@72ba28ee, org.springframework.security.web.savedrequest.RequestCacheAwareFilter@65327f5, org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter@2adddc06, org.springframework.security.web.authentication.AnonymousAuthenticationFilter@17ae7628, org.springframework.security.web.session.SessionManagementFilter@710d7aff, org.springframework.security.web.access.ExceptionTranslationFilter@6569dded, org.springframework.security.web.access.intercept.FilterSecurityInterceptor@38499e48]

```

Indeed it was. If we try to make an unauthenticated request to get a contact, we get

```
curl localhost:8080/api/contact/5 
```

and we get

```json
{
  "timestamp": 1513077790273,
  "status": 403,
  "error": "Forbidden",
  "message": "Access Denied",
  "path": "/api/contact/5"
}
```

Ok, great! We are denied because we specified that every request is authenticated and we're not supplying any credentials. Notice the error code? It is a 403 instead of a 401. We really would like a 401 returned when we are not supplying credentials, but we'll fix that later.

Now, let's create a basic filter:

```java
public class JwtAuthFilter extends GenericFilterBean {
	
	private static final Logger log = LoggerFactory.getLogger(JwtAuthFilter.class);

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		log.info("request received");
		log.info("checking for bearer token in Authorization header");
		
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		
		String authHeaderValue = httpRequest.getHeader("Authorization");
		
		if (authHeaderValue == null) {
			log.info("no Authorization Header");
			log.info("requests should have jwt token in form - Authorization: Bearer <jwt>");
		}
		
		log.info("Authorization header present: " + authHeaderValue);
		
		// extract token from authHeaderValue and use jjwt library to verify
		
		// send request down the chain
		chain.doFilter(request, response);
		
	}

}
```

Now comes the tricky part...where in the default chain do we place our new filter? Let's look at the third chain listed in our logs:

```
Creating filter chain: OrRequestMatcher [requestMatchers=[Ant [pattern='/token']]], [org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter@4905c46b, org.springframework.security.web.context.SecurityContextPersistenceFilter@2d7e1102, org.springframework.security.web.header.HeaderWriterFilter@466d49f0, org.springframework.security.web.authentication.logout.LogoutFilter@72458efc, org.springframework.security.web.authentication.www.BasicAuthenticationFilter@72ba28ee, org.springframework.security.web.savedrequest.RequestCacheAwareFilter@65327f5, org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter@2adddc06, org.springframework.security.web.authentication.AnonymousAuthenticationFilter@17ae7628, org.springframework.security.web.session.SessionManagementFilter@710d7aff, org.springframework.security.web.access.ExceptionTranslationFilter@6569dded, org.springframework.security.web.access.intercept.FilterSecurityInterceptor@38499e48]

```

This is securing the `/token` url which we will use to get tokens, and it is secured by HTTP basic authentication. This was configured automatically by Spring Boot driven by our application properties

```yaml
security:
  user:
    name: chase
    password: changeme
    
  basic:
    path:
    - /token
```

Let's break down the filters that are being applied in this chain:

* WebAsyncManagerIntegrationFilter
* SecurityContextPersistenceFilter
* HeaderWriterFilter
* LogoutFilter
* BasicAuthenticationFilter <--- insert here
* RequestCacheAwareFilter
* SecurityContextHolderAwareRequestFilter
* AnonymousAuthenticationFilter
* SessionManagementFilter
* ExceptionTranslationFilter
* FilterSecurityInterceptor

Since our filter will perform parsing similar to what the `BasicAuthenticationFilter` does (extract the Authorization header, verify the user:password token, populate the SecurityContext), let's put our filter at that location:

```
@Bean
public WebSecurityConfigurerAdapter jwtWebSecurityChain() {
	return new WebSecurityConfigurerAdapter() {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.antMatcher("/api/**")
				.authorizeRequests().anyRequest().authenticated()
				.and()
				.addFilterAt(new JwtAuthFilter(), BasicAuthenticationFilter.class)
				.csrf().disable();
		}
	};
}
```

Checking our filter chain, let's see that it has been added

```
2017-12-12 06:01:39.940  INFO 28865 --- [           main] o.s.s.web.DefaultSecurityFilterChain     : Creating filter chain: Ant [pattern='/api/**'], [org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter@61533ae, org.springframework.security.web.context.SecurityContextPersistenceFilter@796d3c9f, org.springframework.security.web.header.HeaderWriterFilter@757529a4, org.springframework.security.web.authentication.logout.LogoutFilter@17ca8b92, com.drive2code.JwtAuthFilter@732bb66d, org.springframework.security.web.savedrequest.RequestCacheAwareFilter@41e1455d, org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter@7ed9ae94, org.springframework.security.web.authentication.AnonymousAuthenticationFilter@720653c2, org.springframework.security.web.session.SessionManagementFilter@2e1792e7, org.springframework.security.web.access.ExceptionTranslationFilter@2873d672, org.springframework.security.web.access.intercept.FilterSecurityInterceptor@1ee29c84]
```

Ok, good. Our filter doesn't really do anything at this point, so all we should see when we try a request is some log output

```
curl localhost:8080/api/contact/5 -H 'Authorization: Bearer mytoken'

{"timestamp":1513080208520,"status":403,"error":"Forbidden","message":"Access Denied","path":"/api/contact/5"}
```

and the logs show: 

```
2017-12-12 06:03:28.518  INFO 28865 --- [nio-8080-exec-2] com.drive2code.JwtAuthFilter             : request received
2017-12-12 06:03:28.518  INFO 28865 --- [nio-8080-exec-2] com.drive2code.JwtAuthFilter             : checking for bearer token in Authorization header
2017-12-12 06:03:28.518  INFO 28865 --- [nio-8080-exec-2] com.drive2code.JwtAuthFilter             : Authorization header present: Bearer mytoken
```

When we get our jwt, the curl command above shows how we'll pass it in. Let's add a little more logic to parse the bearer token from the header

```java
// extract token from authHeaderValue and use jjwt library to verify
String tokenString = authHeaderValue.trim().split(" ")[1];
log.info("token: " + tokenString);
```

This is just some rough logic for our demo. In production you would be a lot more careful. Let's try the request

```
curl localhost:8080/api/contact/5 -H 'Authorization: Bearer my.jwt'
```

and the logs show

```
2017-12-12 06:13:44.760  INFO 28933 --- [nio-8080-exec-2] com.drive2code.JwtAuthFilter             : request received
2017-12-12 06:13:44.760  INFO 28933 --- [nio-8080-exec-2] com.drive2code.JwtAuthFilter             : checking for bearer token in Authorization header
2017-12-12 06:13:44.760  INFO 28933 --- [nio-8080-exec-2] com.drive2code.JwtAuthFilter             : Authorization header present: Bearer my.jwt
2017-12-12 06:13:44.760  INFO 28933 --- [nio-8080-exec-2] com.drive2code.JwtAuthFilter             : token: my.jwt
```

Sweet. Now the path is clear for what we need to do next. We need to parse the JWT and verify the signature. If it verifies, we can trust the subject (i.e. user) claimed in the token. We only need to add them to the SecurityContext. In fact, let's jump ahead of ourselves a little and add these lines to our filter

```java
log.info("token: " + tokenString);
		
Principal p = new Principal() {			
	@Override
	public String getName() {
		return tokenString;
	}
};

Authentication auth = new UsernamePasswordAuthenticationToken(p, null, null);

SecurityContextHolder.getContext().setAuthentication(auth);
```

Now if we make our request again,

```
curl localhost:8080/api/contact/5 -H 'Authorization: Bearer my.jwt'
{"id":"5","userId":"chase","name":"john doe","phoneNumber":null,"email":"johndoe@example.com"}
```

we get through. The key line is 

```java
SecurityContextHolder.getContext().setAuthentication(auth);
```

which populates the `SecurityContext`. When we decide that our JWT is valid and can be trusted, we simply populate the `SecurityContext` with an `Authentication` token. There's really no magic going on.



