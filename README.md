SAML Protocol middleware to create SAMLP identity providers for node.js.

[![Build Status](https://travis-ci.org/auth0/node-samlp.png)](https://travis-ci.org/auth0/node-samlp)

## Installation

    npm install samlp

## Introduction

This middleware is meant to generate a valid SAML Protocol identity provider endpoint that speaks saml.

The idea is that you will use another mechanism to validate the user first.

The endpoint supports metadata as well in the url ```/FederationMetadata/2007-06/FederationMetadata.xml```.

## Usage

Options

| Name                | Description                                      | Default                                      |
| --------------------|:-------------------------------------------------| ---------------------------------------------|
| cert                | public key used by this identity provider        | REQUIRED                                     |
| key                 | private key used by this identity provider       | REQUIRED                                     |
| getPostURL          | get the url to post the token f(audience, samlRequestDom, req, callback)                | REQUIRED                                     |
| issuer              | the name of the issuer of the token              | REQUIRED                                     |
| audience            | the audience for the saml token                  | req.query.SAMLRequest.Issuer                 |
| getUserFromRequest  | how to extract the user information from request | function(req) { return req.user; }           |
| profileMapper       | mapper to map users to claims (see PassportProfileMapper)| PassportProfileMapper |
| signatureAlgorithm  | signature algorithm, options: rsa-sha1, rsa-sha256 | ```'rsa-sha256'``` |
| digestAlgorithm     | digest algorithm, options: sha1, sha256          | ```'sha256'``` |
| RelayState          | state of the auth process                        | ```req.query.RelayState || req.body.RelayState``` |


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

## SAML Protocol Metadata

This module also support generating SAML Protocol metadata (IDPSsoDescriptor):

~~~javascript
app.get('/samlp/FederationMetadata/2007-06/FederationMetadata.xml', wsfed.metadata({
  issuer:   'the-issuer',
  cert:     fs.readFileSync(path.join(__dirname, 'some-cert.pem')),
}));
~~~

It also accept two optionals parameters:

-  profileMapper: a class implementing the profile mapper. This is used to render the claims type information (using the metadata property). See [PassportProfileMapper](https://github.com/auth0/node-samlp/blob/master/lib/claims/PassportProfileMapper.js) for more information.
-  endpointPath: this is the full path in your server to the auth route. By default the metadata handler uses the metadata request route without ```/FederationMetadata/2007..blabla.```

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## Author

[Auth0](auth0.com)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.
