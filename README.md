SAML Protocol middleware to create SAMLP identity providers for node.js.

![Build Status](https://github.com/auth0/node-samlp/workflows/Tests/badge.svg)

## Installation

    npm install samlp

### Supported Node Versions

node >= 12

## Introduction

This middleware is meant to generate a valid SAML Protocol identity provider endpoint that speaks saml.

The idea is that you will use another mechanism to validate the user first.

The endpoint supports metadata as well in the url ```/FederationMetadata/2007-06/FederationMetadata.xml```.

## Login (Authentication Flow)

### Usage

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
| signResponse        | whether to sign the SAML response                | false                                        |
| signAssertion       | whether to sign the SAML assertion               | true                                         |
| RelayState          | state of the auth process                        | ```req.query.RelayState || req.body.RelayState``` |
| sessionIndex          | the index of a particular session between the principal identified by the subject and the authenticating authority                        | _SessionIndex is not included_ |
| responseHandler       | custom response handler for SAML response f(SAMLResponse, options, req, res, next) | HTML response that POSTS to postUrl |


Add the middleware as follows:

~~~javascript
app.get('/samlp', samlp.auth({
  issuer:     'the-issuer',
  cert:       fs.readFileSync(path.join(__dirname, 'some-cert.pem')),
  key:        fs.readFileSync(path.join(__dirname, 'some-cert.key')),
  getPostURL: function (wtrealm, wreply, req, callback) {
                return callback( null, 'http://someurl.com')
              }
}));
~~~~

## SAML Protocol Metadata

This module also support generating SAML Protocol metadata (IDPSsoDescriptor):

~~~javascript
app.get('/samlp/FederationMetadata/2007-06/FederationMetadata.xml', samlp.metadata({
  issuer:   'the-issuer',
  cert:     fs.readFileSync(path.join(__dirname, 'some-cert.pem')),
}));
~~~

It also accept two optionals parameters:

-  profileMapper: a class implementing the profile mapper. This is used to render the claims type information (using the metadata property). See [PassportProfileMapper](https://github.com/auth0/node-samlp/blob/master/lib/claims/PassportProfileMapper.js) for more information.
-  endpointPath: this is the full path in your server to the auth route. By default the metadata handler uses the metadata request route without ```/FederationMetadata/2007..blabla.```

*Note:* If `x-forwarded-host` or `x-forwarded-proto` are received during the HTTP request to the metadata endpoint the urls contained in the metadata will use those them as host or protocol respectively instead of the original ones from `request.headers.host` and `request.protocol`.

## Logout - SLO (Single Logout)
Starting on version `v2.0` Single Logout is supported (SAML 2.0 Single Logout Profile). General support for SLO among Session Participants is varies a lot. This module supports the following flows:

- IdP Initiated: a logout is initiated by invoking the GET logout endpoint specified in the IdP metadata. The IdP creates a signed SAML `LogoutRequest` and propagates it to the involved Session Participants.
- SP Initiated: a Session Participant starts a SLO by sending a SAML `LogoutRequest` to the IdP. The IdP propagates it to the involved Session Participants.

Both flows need the IdP to accept SAML `LogoutResponses` from the Session Participants. This is also supported by this module.

### Usage

Options

| Name                | Description                                      | Default                                          |
| --------------------|:-------------------------------------------------| -------------------------------------------------|
| cert                | public key used by this identity provider        | REQUIRED                                         |
| key                 | private key used by this identity provider       | REQUIRED                                         |
| issuer              | the name of the issuer of the token              | REQUIRED                                         |
| protocolBinding     | the binding to use                               | 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' |
| sessionParticipants | an object that handles Session Participants. Check [this implementation](./lib/sessionParticipants/index.js) | An empty object. It is REQUIRED if you want to use SLO          |
| clearIdPSession     | a function to be called when the logout process is finished so the IdP can clean its session | function (cb){ return cb(); |
| store               | an object that handles the HTTP Session. Check [this implementation](./test/in_memory_store/) | new SessionStore(options) Uses req.session to store the current state |

#### Notes

- options.cert: This is the public certificate of the IdP
- options.key: This is the private key of the IdP. The IdP will sign its SAML `LogoutRequest` and `LogoutResponse` with this key.
- options.store: Since the logout flow will involve several requests/responses, we need to keep track of the transaction state. The default implementation uses req.session to store the transaction state via the 'flowstate' module
- options.sessionParticipants: Will handle SessionParticipant objects. Each SessionParticipant object needs to have the following structure:

```js
var sessionParticipant = {
  serviceProviderId : 'https://foobarsupport.zendesk.com', // The Issuer (Session Participant id)
  nameId: 'foo@example.com', // NameId Of the logged in user in the SP
  nameIdFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient', // Format of the NameId
  sessionIndex: '1', // The session index generated by the IdP
  serviceProviderLogoutURL: 'https://foobarsupport.zendesk.com/logout', // The logout URL of the Session Participant
  cert: sp1_credentials.cert, // The Session Participant public certificate, used to verify the signature of the SAML requests made by this SP
  binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' // Optional, participant-specific binding to use during SLO, if not provided - will use "protocolBinding" from provided options
};
```

In some situations it is possible for session participants to have mixed bindings during one Single Log Out (SLO) transaction. By default the library will use the binding specified in `options.protocolBinding`, however if mixed bindings must be used - each participant must have the binding specified as an additional field. If the binding value is invalid - it will fall back to `HTTP-POST`.

Add the middleware as follows:

~~~javascript
  app.get('/logout', samlp.logout({
      deflate:            true,
      issuer:             'the-issuer',
      protocolBinding:    'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
      cert:               fs.readFileSync(path.join(__dirname, 'some-cert.pem')),
      key:                fs.readFileSync(path.join(__dirname, 'some-cert.key'))
  }));

  app.post('/logout', samlp.logout({
      issuer:             'the-issuer',
      protocolBinding:    'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      cert:               fs.readFileSync(path.join(__dirname, 'some-cert.pem')),
      key:                fs.readFileSync(path.join(__dirname, 'some-cert.key'))
  }));
~~~~

## Error handling

Errors are not sent back to the SP. To do so, you'll need to use the `sendError` middleware.

~~~javascript
samlp.sendError({
    RelayState:         'relayState',
    issuer:             'the-issuer',
    signatureAlgorithm: 'rsa-sha1',
    digestAlgorithm:    'sha1',
    cert:               fs.readFileSync(path.join(__dirname, 'some-cert.pem')),
    key:                fs.readFileSync(path.join(__dirname, 'some-cert.key')),
    error: { description: err.message },
    getPostURL: function (req, callback) {
      callback(null, 'http://someurl.com');
    }
})(req, res, next);
~~~~

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## Author

[Auth0](auth0.com)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.
