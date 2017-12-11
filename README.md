# Spring Security Lab

A lab environment for experiments with Spring Security.

## Usage

Use `git checkout master` to reset this project back to the defaults and start a new lab. From here, create a new branch for your experiment and name it something appropriate like

```
git checkout -b jwt-lab
```

## Lab: JSON Web Token (JWT)

In this lab, we will an end point `/token` that is protected with HTTP basic authentication and issues a jwt with the user name as the subject claim if the user successfully authenticates. Then we will expose an API under `/api` and protect the url pattern `/api/**` with a stateless filter that performs the following check:

1. If the header `Authentication: Bearer <jwt>` is not present, reject the request.
2. Otherwise, extract the token, verify it, and populate the `SecurityContextHolder` with an authenticated principal using nothing but the verified token.

Once this is done, we will add a scope claim to the JWT that maps to roles in our Spring Security configuration. We will change the `/token` end point to recover the roles from the `UserDetailsService` and add them to the issued jwt as a scope claim. We will then change the JWT filter to populate the roles for the authenticated principal on every new request.

With that out of the way, let's get to work!

### The Problem Domain

We really need something a little more interesting to give us some context, so let's design a small REST API that manages contacts for the users of our application.

Let's start by defining a POJO (plain old Java object) to hold data for a single contact:

```java
public class Contact {
	public String id;
	public String userId;
	public String name;
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
