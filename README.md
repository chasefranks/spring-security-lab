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
	public int id; // an id to reference a contact
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

### Writing Our Own Security Filter

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


### Verifying the JWT

To verify Json web tokens, we will use the [JJWT](https://github.com/jwtk/jjwt) library. We just need to add the dependency to our build.gradle file

```
dependencies {
	...
	compile('io.jsonwebtoken:jjwt:0.9.0')
	...
}
```

Let's keep it really simple and start by creating a service that will verify signed JWTs for us

```java
public class JwtService {
	
	private final String secret;	
	
	public JwtService(String secret) {
		this.secret = secret;
	}

	public String verifyToken(String tokenString) {		
		Jws<Claims> claims = Jwts.parser()
			.setSigningKey(secret.getBytes())
			.parseClaimsJws(tokenString); // this throws a number of exceptions
		
		return claims.getBody().getSubject();			
	}

}
```

Note, in the body of the `verifyToken` we are using the JJWT library. 

To use it, we create it as a bean using a new property called `jwt.secret`

```yaml
# application.yml
    
jwt:
  secret: thesecretgarden
```

```java
@Bean
public JwtService jwtService(@Value("${jwt.secret}") String secret) {
	return new JwtService(secret);
}
```

Finally, in our `JwtAuthFilter#doFilter` method, we can call our new service

```java
String subject = jwtService.verifyToken(tokenString);
		
log.info("jwt verified: subject = {}", subject);

// use this logic to populate the SecurityContext if the jwt is valid		
Principal p = new Principal() {			
	@Override
	public String getName() {
		return subject;
	}
};

Authentication auth = new UsernamePasswordAuthenticationToken(p, null, null);

log.info("adding authentication {} to the SecurityContext", auth);
SecurityContextHolder.getContext().setAuthentication(auth);
```

Ok, let's try it out. First, let's try the 'happy path'. Go over to [jwt.io](https://jwt.io/) and let's create a token using our secret. The jwt I created has this structure:

```json
// header
{
  "alg": "HS256",
  "typ": "JWT"
}
// payload
{
  "sub": "chase",
  "name": "Chase Franks",
  "exp": 1513114776
}
```

and using the secret 'thesecretgarden', we get the token

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjaGFzZSIsIm5hbWUiOiJDaGFzZSBGcmFua3MiLCJleHAiOjE1MTMxMTQ3NzZ9.GtDIWF14w_jcdEJe08ethK5Cy_idGmoaNp2NZ1Rv7mo
```

Let's try passing it to the service:

```
curl localhost:8080/api/contact/12 \
-H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjaGFzZSIsIm5hbWUiOiJDaGFzZSBGcmFua3MiLCJleHAiOjE1MTMxMTQ3NzZ9.GtDIWF14w_jcdEJe08ethK5Cy_idGmoaNp2NZ1Rv7mo'
```

It works

```
{"id":"12","userId":"chase","name":"john doe","phoneNumber":null,"email":"johndoe@example.com"}
```

and the log shows

```
2017-12-12 15:02:59.482  INFO 33212 --- [io-8080-exec-10] com.drive2code.JwtAuthFilter             : request received
2017-12-12 15:02:59.482  INFO 33212 --- [io-8080-exec-10] com.drive2code.JwtAuthFilter             : checking for bearer token in Authorization header
2017-12-12 15:02:59.482  INFO 33212 --- [io-8080-exec-10] com.drive2code.JwtAuthFilter             : Authorization header present: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjaGFzZSIsIm5hbWUiOiJDaGFzZSBGcmFua3MiLCJleHAiOjE1MTMxMTQ3NzZ9.GtDIWF14w_jcdEJe08ethK5Cy_idGmoaNp2NZ1Rv7mo
2017-12-12 15:02:59.482  INFO 33212 --- [io-8080-exec-10] com.drive2code.JwtAuthFilter             : token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjaGFzZSIsIm5hbWUiOiJDaGFzZSBGcmFua3MiLCJleHAiOjE1MTMxMTQ3NzZ9.GtDIWF14w_jcdEJe08ethK5Cy_idGmoaNp2NZ1Rv7mo
2017-12-12 15:02:59.484  INFO 33212 --- [io-8080-exec-10] com.drive2code.JwtAuthFilter             : jwt verified: subject = chase
2017-12-12 15:02:59.484  INFO 33212 --- [io-8080-exec-10] com.drive2code.JwtAuthFilter             : adding authentication org.springframework.security.authentication.UsernamePasswordAuthenticationToken@95e952f5: Principal: com.drive2code.JwtAuthFilter$1@6a16ad31; Credentials: [PROTECTED]; Authenticated: true; Details: null; Not granted any authorities to the SecurityContext
```

Nice! Progressing right along. 

There are a number of things that can go wrong verifying a JWT. Let's see what happens when we try to tamper with the identity. Let's change the subject in the claim to john, but leave the signature the same. The jwt I get from jwt.io looks like (just the altered payload section...remember jwts look like header.payload.signature)

```
eyJzdWIiOiJqb2huIiwibmFtZSI6IkNoYXNlIEZyYW5rcyIsImV4cCI6MTUxMzExNDc3Nn0
```

Passing this in with the same header and signature portions as above, we get

```
curl localhost:8080/api/contact/2 -H \
'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqb2huIiwibmFtZSI6IkNoYXNlIEZyYW5rcyIsImV4cCI6MTUxMzExNDc3Nn0.GtDIWF14w_jcdEJe08ethK5Cy_idGmoaNp2NZ1Rv7mo'


{"timestamp":1513113668271,"status":500,"error":"Internal Server Error","exception":"io.jsonwebtoken.SignatureException","message":"JWT signature does not match locally computed signature. JWT validity cannot be asserted and should not be trusted.","path":"/api/contact/2"}
```

This shows that we can't tamper with the identity, without regenerating the signature, hence knowing the secret.

Similarly, using the expired but cryptographically valid token

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqb2huIiwibmFtZSI6IkNoYXNlIEZyYW5rcyIsImV4cCI6MTUxMzExMDAwMH0.xMMdQ8yHLQfKOVPRWNEh3wTZytSo9scQVCRoxUA1qyo
```

```json
{
    "timestamp": 1513113891585,
    "status": 500,
    "error": "Internal Server Error",
    "exception": "io.jsonwebtoken.ExpiredJwtException",
    "message": "JWT expired at 2017-12-12T14:20:00Z. Current time: 2017-12-12T15:24:51Z, a difference of 3891583 milliseconds.  Allowed clock skew: 0 milliseconds.",
    "path": "/api/contact/12"
}
```

We now have a stateless mechanism for authenticating a user. Every request is authenticated with a jwt which asserts the user's identity, and then forgotten after the request is served. Almost...

Run the previous curl command with extra verbose output added

```
curl localhost:8080/api/contact/12 \
-H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjaGFzZSIsIm5hbWUiOiJDaGFzZSBGcmFua3MiLCJleHAiOjE1MTMxMTQ3NzZ9.GtDIWF14w_jcdEJe08ethK5Cy_idGmoaNp2NZ1Rv7mo' -vvvv
```

```
*   Trying ::1...
* TCP_NODELAY set
* Connected to localhost (::1) port 8080 (#0)
> GET /api/contact/12 HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/7.54.0
> Accept: */*
> Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjaGFzZSIsIm5hbWUiOiJDaGFzZSBGcmFua3MiLCJleHAiOjE1MTMxMTQ3NzZ9.GtDIWF14w_jcdEJe08ethK5Cy_idGmoaNp2NZ1Rv7mo
> 
< HTTP/1.1 200 
< X-Content-Type-Options: nosniff
< X-XSS-Protection: 1; mode=block
< Cache-Control: no-cache, no-store, max-age=0, must-revalidate
< Pragma: no-cache
< Expires: 0
< X-Frame-Options: DENY
< Set-Cookie: JSESSIONID=8943D4B4ED2882AE9222EAE4D2F609FE; Path=/; HttpOnly
< Content-Type: application/json;charset=UTF-8
< Transfer-Encoding: chunked
< Date: Tue, 12 Dec 2017 21:30:18 GMT
< 
* Connection #0 to host localhost left intact
{"id":"12","userId":"chase","name":"john doe","phoneNumber":null,"email":"johndoe@example.com"}
```

See that little guy 

```
Set-Cookie: JSESSIONID=8943D4B4ED2882AE9222EAE4D2F609FE; Path=/; HttpOnly
```

Retry the request with the session id passed as a cookie. We sort of get through but it looks like the output stream gets interupted...

```
curl localhost:8080/api/contact/12 -b 'JSESSIONID=8943D4B4ED2882AE9222EAE4D2F609FE'
curl: (18) transfer closed with outstanding read data remaining
{"id":"12","userId":"chase","name":"john doe","phoneNumber":null,"email":"johndoe@example.com"}{"timestamp":1513114382341,"status":200,"error":"OK","exception":"java.lang.NullPointerException","message":"No message available","path":"/api/contact/12"}
```

Since we got our single hard-coded contact, we made it through the filter chain. It bombed out on the response end of the filter, and I'll explain that later, but let's just ignore that for now. How did we make it through without credentials?

The JSESSIONID cookie is the name of the session id created by all J2EE compliant servers when they create a session, and that's exactly what happened in the first request with the credentials. Now, the default behavior of Spring Security is to cache the authenticated principal in the session. So by passing the session id, we are using the stateful session with id 8943D4B4ED2882AE9222EAE4D2F609FE, and which contains our principal.

It sounds convenient, but there's an architectural consideration here I've been hinting at all along. RESTful web services usually do not retain any state. Every request is treated as a new anonymous request when it arrives. The 'state' lives in the resources themselves, and we don't want anything to creep into the infrastructure. This is the guiding principle of REST, so that session is waiting for someone (like a developer) to start storing things in it.

With this in mind, do me a solid and configure the session management this way in our  `WebSecurityConfigurerAdapter` bean

```java
protected void configure(HttpSecurity http) throws Exception {
	http.antMatcher("/api/**")
		.authorizeRequests().anyRequest().authenticated()
		.and()
		.addFilterAt(new JwtAuthFilter(jwtService), BasicAuthenticationFilter.class)
		.csrf().disable()
		.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
}

```

Now sessions will never be created.

```
curl localhost:8080/api/contact/12 -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqb2huIiwibmFtZSI6IkNoYXNlIEZyYW5rcyIsImV4cCI6MTUxMzExOTYwMH0.IT1CaYaWil1UbJ2somkyruLz6Z-baHhkXlfHw7yHhVI' -vvvv
*   Trying ::1...
* TCP_NODELAY set
* Connected to localhost (::1) port 8080 (#0)
> GET /api/contact/12 HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/7.54.0
> Accept: */*
> Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqb2huIiwibmFtZSI6IkNoYXNlIEZyYW5rcyIsImV4cCI6MTUxMzExOTYwMH0.IT1CaYaWil1UbJ2somkyruLz6Z-baHhkXlfHw7yHhVI
> 
< HTTP/1.1 200 
< X-Content-Type-Options: nosniff
< X-XSS-Protection: 1; mode=block
< Cache-Control: no-cache, no-store, max-age=0, must-revalidate
< Pragma: no-cache
< Expires: 0
< X-Frame-Options: DENY
< Content-Type: application/json;charset=UTF-8
< Transfer-Encoding: chunked
< Date: Tue, 12 Dec 2017 21:48:08 GMT
< 
* Connection #0 to host localhost left intact
{"id":"12","userId":"chase","name":"john doe","phoneNumber":null,"email":"johndoe@example.com"}
```

### Making Our Contact Service Interesting

Let's apply what we have so far to our contact service. The key idea here is that the authenticated principal object is automatically injected into any `@RestController` handler that declares a `Principal` object in it's signature.

For example, let's change the method that handles the protected route `/api/contact/{id}` to this

```java
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
```

and let's actually add a method that allows us to create contacts. In REST, creating resources is done with the POST verb, so we add

```java
@PostMapping
public Contact createContact(@RequestBody Contact c, Principal p) {
	return contactService.createContact(c, p.getName());
}
```

The `ContactService` class we've added is a service that stores contacts in memory using a table that maps ids to instances of our `Contact` class. All we do is pass along the principal's name and quietly set this to the `Contact.userId` property. This ensures that the newly created contact is owned by the authenticated principal making the request.

Ok, let's fire up the service, get a jwt from jwt.io, and add a contact. Here's our JWT

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkcmV2aWwiLCJuYW1lIjoiRG9jdG9yIEV2aWwiLCJleHAiOjE1MTMyMDYwMDB9.kZwUIM55Kf_oX4AHO9I9ZcBXJp0awDzME0k-6FwDEZk
```

which has payload

```json
{
  "sub": "drevil",
  "name": "Doctor Evil",
  "exp": 1513206000
}
```

I set the expiration date to give Dr. Evil till close of business today to run his evil authenticated experiments!

Now let's create a contact for his favorite cat

```
curl -XPOST localhost:8080/api/contact -d '
{
  "name": "Mr Bigglesworth",
  "email": "imacat@catscanttype.com",
  "phoneNumber": "000-111-2222"
}' -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkcmV2aWwiLCJuYW1lIjoiRG9jdG9yIEV2aWwiLCJleHAiOjE1MTMyMDYwMDB9.kZwUIM55Kf_oX4AHO9I9ZcBXJp0awDzME0k-6FwDEZk' -H 'Content-Type: application/json'
```

and we get

```json
{
  "id": 31796,
  "userId": "drevil",
  "name": "Mr Bigglesworth",
  "phoneNumber": "000-111-2222",
  "email": "imacat@catscanttype.com"
}
```

The id 31796 was randomly generated by the `ContactService`, and notice that the `userId` has the subject claimed in the token. Everything looks like it's working. Let's make sure we can retrieve it. To make things a little more convenient, let's save our jwt in an environment variable

```
export EVILS_JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkcmV2aWwiLCJuYW1lIjoiRG9jdG9yIEV2aWwiLCJleHAiOjE1MTMyMDYwMDB9.kZwUIM55Kf_oX4AHO9I9ZcBXJp0awDzME0k-6FwDEZk
```

Now we can do (note the change from single to double quotes)

```
curl localhost:8080/api/contact/31796 -H "Authorization: Bearer $EVILS_JWT"
```

and we get our contact

```json
{
  "id": 31796,
  "userId": "drevil",
  "name": "Mr Bigglesworth",
  "phoneNumber": "000-111-2222",
  "email": "imacat@catscanttype.com"
}
```

To test this out, let's create another identity using jwt.io to generate the token

```
export AUSTINS_JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhcG93ZXJzIiwibmFtZSI6IkF1c3RpbiBQb3dlcnMiLCJleHAiOjE1MTMyMDYwMDB9.myb-5XSDRKmJvraXt56jlUwp-ChNkw4r2ZA3nXzj1B8
```

and POST new contact for Austin Powers

```
curl -XPOST localhost:8080/api/contact -H "Authorization: Bearer $AUSTINS_JWT" -d '
{
   "name": "Fat Bastard",
   "email": "wantmybabyback@example.com"
}' -H 'Content-Type: application/json'
```

Our new contact looks like

```json
{"id":25293,"userId":"apowers","name":"Fat Bastard","phoneNumber":null,"email":"wantmybabyback@example.com"}
```

Let's try to access this new contact with Dr Evils identity

```
curl localhost:8080/api/contact/25293 -H "Authorization: Bearer $EVILS_JWT" -v
```

We get

```
*   Trying ::1...
* TCP_NODELAY set
* Connected to localhost (::1) port 8080 (#0)
> GET /api/contact/25293 HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/7.54.0
> Accept: */*
> Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkcmV2aWwiLCJuYW1lIjoiRG9jdG9yIEV2aWwiLCJleHAiOjE1MTMyMDYwMDB9.kZwUIM55Kf_oX4AHO9I9ZcBXJp0awDzME0k-6FwDEZk
> 
< HTTP/1.1 403 
< X-Content-Type-Options: nosniff
< X-XSS-Protection: 1; mode=block
< Cache-Control: no-cache, no-store, max-age=0, must-revalidate
< Pragma: no-cache
< Expires: 0
< X-Frame-Options: DENY
< Content-Type: text/plain;charset=UTF-8
< Content-Length: 25
< Date: Wed, 13 Dec 2017 18:22:46 GMT
< 
* Connection #0 to host localhost left intact
can't access this contact
```

Note the 403 status code that we're returning from our handler method.

Ok, we now have a functioning API for storing contacts secured by Json web tokens. Any one with a valid token can securely store and access contacts. The problem is we don't really have any control over who our users are, so let's go back to that `/token` end point we secured with basic authentication using the Spring Boot defaults. The last step is to create a store of predefined users using the in-memory user details service, wire that into the default authentication manager, and implement the handler to return a token based on the user details.











