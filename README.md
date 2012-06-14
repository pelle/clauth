# clauth - OAuth 2 based simple authentication system for Clojure Ring

[![Build Status](https://secure.travis-ci.org/pelle/clauth.png)](http://travis-ci.org/pelle/clauth)

This is a simple OAuth 2 provider that is designed to be used as a primary authentication provider for a Clojure Ring app.

It currently handles OAuth2 bearer authentication and interactive authentication. 

See [draft-ietf-oauth-v2-bearer](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08)

The following bearer tokens are implemented:

* [Authorization header](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.1)
* [Form encoded body parameter](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.2)
* [URI query field](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.3)
* Non standard http cookie ('access_token') for use in interactive applications
* Non standard session ('access_token') for use in interactive applications

## Install

Add the following dependency to your `project.clj` file:

```clojure
[clauth "1.0.0-rc9"]
```

## Usage

There are currently 2 middlewares defined:

* wrap-bearer-token
* require-bearer-token!

Both of them take as a parameter a function which should return a object representing the token. This could be a user object, but could also be a token object with specific meta-data. I may standardize on something when more of the framework is developed.

The object returned by your function is set to :access-token entry in the request.

The difference between wrap-bearer-token and require-bearer-token! is that wrap will find a token but not require it. require-bearer-token will return a [HTTP 401 header](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.4).

## Grant Types

Currently the following Grant types are supported:

* [Authorization Code Grant](http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-4.1)
* [Client Credential Grant](http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-4.4)
* [Resource Owner Password Credential Grant](http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-4.3)

Grant types are implemented using multimethods. To implement one 

```clojure
(defmethod token-request-handler "my_grant_type" [req authenticator] ...)
```

## Authorization request

We currently support the following authorization requests:

* [Authorization Code Grant](http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-4.1)
* [Implicit Grant](http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-4.2)

## Tokens

There is a protocol defined called Expirable which implements one function:

```clojure
(is-valid? token)
```

This is implementend by IPersistentMap so {} represents a valid token where {:expires (date-time 2011)} is invalid.

A OAuthToken record exists which can be instantiated and stored easily by the create-token function:

```clojure
(create-token client user)
```

## Client Applications

A ClientApplication record exists which can be instantiated and stored easily by the register-app function:

```clojure
(register-app name url)
```

A client application has a client-id and a client-secret which is used for issuing tokens.

## Users

A User record exists which can be instantiated and stored easily by the register-user function:

```clojure
(register-user login password name url)
```

## Stores

Stores are used to store tokens and will be used to store clients and users as well.

There is a generalized protocol called Store and currently a simple memory implementation used for it.

It should be pretty simple to implement this Store with redis, sql, datomic or what have you. 

It includes a simple Redis implementation.

The stores used by the various parts are defined in an atom for each type. reset! each of them with your own implementation.

The following stores are currently defined:

* token-store is in clauth.token/token-store
* auth-code-store is in clauth.auth-code/auth-code-store
* client-store is in clauth.client/client-store
* user-store is in clauth.user/user-store

To use the redis store add the following to your code:

```clojure
(reset! token-store (create-redis-store "tokens"))
(reset! auth-code-store (create-redis-store "auth-codes"))
(reset! client-store (create-redis-store "clients"))
(reset! user-store (create-redis-store "users"))
```

And wrap your handler with a redis connection middleware similar to this: 

```clojure
(defn wrap-redis-store [app]
  (fn [req]
    (redis/with-server
     {:host "127.0.0.1"
      :port 6379
      :db 14
     }
     (app req))))
```

## Authorization OAuth Tokens

There is currently a single authorization-handler that handles authorization called authorization-handler. Install it in your routes by convention at "/authorize" or "/oauth/authorize". 

```clojure
(defn routes [req]
  (case (req :uri)
    "/authorize" ((authorization-handler) req )
    ((require-bearer-token! handler) req)))
```

Authorization handler comes with defaults that use the various built in token, user etc. stores. You can override these by passing in a configuration map containing functions.

```clojure
(authorization-handler {:authorization-form authorization-form-handler
                        :client-lookup clauth.client/fetch-client
                        :token-lookup clauth.token/fetch-token
                        :token-creator clauth.token/create-token 
                        :auth-code-creator clauth.auth-code/create-auth-code})
```

## Issuing OAuth Tokens

There is currently a single token-handler that provides token issuance called token-handler. Install it in your routes by convention at "/token" or "/oauth/token". 

```clojure
(defn routes [req]
  (case (req :uri)
    "/token" ((token-handler) req )
    ((require-bearer-token! handler) req)))
```

Token handler comes with defaults that use the various built in token, user etc. stores. You can override these by passing in a configuration map containing functions.

```clojure
(token-handler {:client-authenticator clauth.client/authenticate-client 
                :user-authenticator clauth.user/authenticate-user
                :token-creator clauth.token/create-token
                :auth-code-revoker clauth.auth-code/revoke-auth-code! 
                :auth-code-lookup clauth.auth-code/fetch-auth-code })
```

## Using as primary user authentication on server

One of the ideas of this is using OAuth tokens together with traditional sessions based authentication providing the benefits of both. To do this we create a new token when a user logs in and adds it to the session.

Why is this a good idea?

* You will be able to view a list of other sessions going on for security purposes
* You will be able to remotely log of another session
* Your app deals with tokens only. So this is also ideal for an API with a javascript front end

To use this make sure to wrap the session middleware. We have a login handler endpoint that could be used like this:

```clojure
(defn routes [master-client]
  (fn [req]
  (case (req :uri)
    "/login" ((login-handler master-client) req )
    ((require-bearer-token! handler) req))))
```

The master-client is a client record representing your own application. A default login view is defined in clauth.views/login-form-handler but you can add your own. This just needs to be a ring handler presenting a form with the parameters "username" and "password".

```clojure
(defn routes [master-client]
  (fn [req]
  (case (req :uri)
    "/login" ((login-handler my-own-login-form-handler master-client) req )
    ((require-bearer-token! handler) req))))
```

## Run Demo App

A mini server demo is available. It creates a client for you and prints out instructions on how to issue tokens with curl.

```
lein run -m clauth.demo
```

## TODO

The goal is to implement the full [OAuth2 spec](http://tools.ietf.org/html/draft-ietf-oauth-v2-25). The only main feature missing is. I'll aim for that for 1.1 as most people currently don't use refresh tokens:

* [Refresh Tokens](http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-1.5)

## Contribute

You will need to have a Redis database running in the background in order to have some of the tests pass, otherwise, you will get an error about the connection being refused.

If you have Homebrew on Mac OSX, you can get Redis by typing ```brew install redis``` in the command line. Once that's done, get the Redis database started in your Terminal window by typing the following:

```
redis-server /usr/local/etc/redis.conf
```

## License

Copyright (C) 2012 Pelle Braendgaard http://stakeventures.com

Distributed under the Eclipse Public License, the same as Clojure.
