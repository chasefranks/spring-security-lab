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
