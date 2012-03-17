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

A OAuthToken record exists which can be instantiated easily by the oauth_token function:

   (oauth-token client user)

Currently an in memory store is used. Use create-token to create and store the token.

I will create a protocol to be used for this so it can be extended with sql/redis etc implementations.

## Run Demo App

A mini server demo is available. It creates a client for you and prints out instructions on how to issue tokens with curl.

    lein run

## TODO

The goal is to implement the full [OAuth2 spec](http://tools.ietf.org/html/draft-ietf-oauth-v2-25) in this order:

* Token Store protocol
* User Store protocol
* [Resource Owner Password Credential Grant](http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-4.3)
* Client Store protocol
* [Authorization Code Grant](http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-4.1)
* [Implicit Grant](http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-4.2)
* [Refresh Tokens](http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-1.5)

## License

Copyright (C) 2012 Pelle Braendgaard http://stakeventures.com

Distributed under the Eclipse Public License, the same as Clojure.
