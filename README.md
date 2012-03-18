# clauth - OAuth 2 based simple authentication system for Clojure Ring

[![Build Status](https://secure.travis-ci.org/pelle/clauth.png)](http://travis-ci.org/pelle/clauth)

This is a simple OAuth 2 provider that is designed to be a primary authentication provider for a Clojure Ring app.

It is under development by a Clojure novice. Please help give feedback on use of idiomatic clojure.

It currently only handles OAuth2 bearer authentication and not the full OAuth2 authorization flow. This will be added.

See [draft-ietf-oauth-v2-bearer](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08)

The following bearer tokens are implemented:

* [Authorization header](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.1)
* [Form encoded body parameter](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.2)
* [URI query field](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.3)
* Non standard http cookie ('access_token') for use in interactive applications

## Usage

There are currently 2 middlewares defined:

* wrap-bearer-token
* require-bearer-token!

Both of them take as a parameter a function which should return a object representing the token. This could be a user object, but could also be a token object with specific meta-data. I may standardize on something when more of the framework is developed.

The object returned by your function is set to :access-token entry in the request.

The difference between wrap-bearer-token and require-bearer-token! is that wrap will find a token but not require it. require-bearer-token will return a [HTTP 401 header](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.4).

## Grant Types

Currently the following Grant types are supported:

* [Client Credential Grant](http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-4.4)

Grant types are implemented using multimethods. To implement one 

    (defmethod token-request-handler "my_grant_type" [req authenticator] ...)

## Tokens

There is a protocol defined called Expirable which implements one function:

    (is-valid? token)

This is implementend by IPersistentMap so {} represents a valid token where {:expires (date-time 2011)} is invalid.

A OAuthToken record exists which can be instantiated and stored easily by the create-token function:

    (create-token client user)

## Client Applications

A ClientApplication record exists which can be instantiated and stored easily by the register-app function:

    (register-app name url)

A client application has a client-id and a client-secret which is used for issuing tokens.

## Stores

Stores are used to store tokens and will be used to store clients and users as well.

There is a generalized protocol called Store and currently a simple memory implementation used for it.

It should be pretty simple to implement this Store with redis, sql, datomic or what have you. I will write a reference implementation using redis next.

The token-store used is set in the atom clauth.token/token-store. reset! it with your own implementation.

## Run Demo App

A mini server demo is available. It creates a client for you and prints out instructions on how to issue tokens with curl.

    lein run

## TODO

The goal is to implement the full [OAuth2 spec](http://tools.ietf.org/html/draft-ietf-oauth-v2-25) in this order:

* User Store
* Redis Store implementation
* [Resource Owner Password Credential Grant](http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-4.3)
* [Authorization Code Grant](http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-4.1)
* [Implicit Grant](http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-4.2)
* [Refresh Tokens](http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-1.5)

## License

Copyright (C) 2012 Pelle Braendgaard http://stakeventures.com

Distributed under the Eclipse Public License, the same as Clojure.
