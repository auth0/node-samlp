SAML Protocol middleware for node.js.

[![Build Status](https://travis-ci.org/auth0/node-samlp.png)](https://travis-ci.org/auth0/node-samlp)

## Installation

    npm install samlp

## Introduction

This middleware is meant to generate a valid SAML Protocol endpoint that talks saml.

The idea is that you will use another mechanism to validate the user first.

The endpoint supports metadata as well in the url ```/FederationMetadata/2007-06/FederationMetadata.xml```.

## Usage

Options

| Name                | Description                                      | Default                                      |
| --------------------|:-------------------------------------------------| ---------------------------------------------|
| cert                | public key used by this identity provider        | REQUIRED                                     |
| key                 | private key used by this identity provider       | REQUIRED                                     |
| getPostURL          | get the url to post the token f(wtrealm, wreply, req, callback)                | REQUIRED                                     |
| issuer              | the name of the issuer of the token              | REQUIRED                                     |
| audience            | the audience for the saml token                  | req.query.wtrealm || req.query.wreply        |
| getUserFromRequest  | how to extract the user information from request | function(req) { return req.user; }           |
| profileMapper       | mapper to map users to claims (see PassportProfileMapper)| PassportProfileMapper |
| signatureAlgorithm  | signature algorithm, options: rsa-sha1, rsa-sha256 | ```'rsa-sha256'``` |
| digestAlgorithm     | digest algorithm, options: sha1, sha256          | ```'sha256'``` |
| RelayState          | state of the auth process                        | ```req.query.RelayState``` |


Add the middleware as follows:

~~~javascript
app.get('/samlp', samlp.auth({
  issuer:     'the-issuer',
  cert:       fs.readFileSync(path.join(__dirname, 'some-cert.pem')),
  key:        fs.readFileSync(path.join(__dirname, 'some-cert.key')),
  getPostUrl: function (wtrealm, wreply, req, callback) { 
                return cb( null, 'http://someurl.com')
              }
}));
~~~~

## WsFederation Metadata

wsfed can generate the metadata document for wsfederation as well. Usage as follows:

~~~javascript
app.get('/samlp/FederationMetadata/2007-06/FederationMetadata.xml', wsfed.metadata({
  issuer:   'the-issuer',
  cert:     fs.readFileSync(path.join(__dirname, 'some-cert.pem')),
}));
~~~

It also accept two optionals parameters:

-  profileMapper: a class implementing the profile mapper. This is used to render the claims type information (using the metadata property). See [PassportProfileMapper](https://github.com/auth0/node-samlp/blob/master/lib/claims/PassportProfileMapper.js) for more information.
-  endpointPath: this is the full path in your server to the auth route. By default the metadata handler uses the metadata request route without ```/FederationMetadata/2007..blabla.```

## License

MIT - AUTH0 2013!