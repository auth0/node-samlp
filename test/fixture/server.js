var express = require('express');
var bodyParser = require('body-parser');
var expressSession = require('express-session');
var http = require('http');
var samlp = require('../../lib');
var xtend = require('xtend');
var fs = require('fs');
var path = require('path');

var fakeUser = {
  id: 12345678,
  displayName: 'John Foo', // 'John Flatabøáíéíáíðøßdœïvn'
  name: {
    familyName: 'Foo',
    givenName: 'John'
  },
  emails: [
    {
      type: 'work',
      value: 'jfoo@gmail.com'
    }
  ]
};

var credentials = {
  cert:     fs.readFileSync(path.join(__dirname, 'samlp.test-cert.pem')),
  key:      fs.readFileSync(path.join(__dirname, 'samlp.test-cert.key')),
  pkcs7:    fs.readFileSync(path.join(__dirname, 'samlp.test-cert.pb7'))
};

module.exports.options = {};

module.exports.start = function(options, callback){
  module.exports.options = options;
  if (typeof options === 'function') {
    callback = options;
    module.exports.options = {};
  }

  var app = express();
  app.use(bodyParser.urlencoded({ extended: true }));
  app.use(express.json());
  app.use(function(req,res,next){
    req.user = fakeUser;
    next();
  });
  app.use(expressSession({secret:'somesecrettokenhere'}));

  function getPostURL (wtrealm, wreply, req, callback) {
    callback(null, 'http://office.google.com');
  }

  //configure samlp middleware
  app.get('/samlp', function(req, res, next) {
    samlp.auth(xtend({}, {
      issuer:             'urn:fixture-test',
      getPostURL:         getPostURL,
      cert:               credentials.cert,
      key:                credentials.key
    }, module.exports.options))(req, res, function(err){
      if (err) {
        return res.send(400, err.message);
      } 
      next();
    });
  });

  app.get('/samlp/FederationMetadata/2007-06/FederationMetadata.xml', samlp.metadata({
    issuer:           'urn:fixture-test',
    cert:             credentials.cert,
    redirectEndpointPath: '/samlp/123',
    postEndpointPath:     '/login/callback'
  }));

  app.get('/logout', function(req, res, next) {
    samlp.logout(xtend({}, {
      deflate:            true,
      issuer:             'urn:fixture-test',
      protocolBinding:    'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
      cert:               credentials.cert,
      key:                credentials.key
    }, module.exports.options))(req, res, function (err) {
      if (err) {
        return res.send(400, err.message);
      } 
      next();
    });
  });

  app.post('/logout', function(req, res, next) {
    samlp.logout(xtend({}, {
      issuer:             'urn:fixture-test',
      protocolBinding:    'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      cert:               credentials.cert,
      key:                credentials.key
    }, module.exports.options))(req, res, function (err) {
      if (err) {
        return res.send(400, err.message);
      } 
      next();
    });
  });

  var server = http.createServer(app).listen(5050, callback);
  module.exports.close = server.close.bind(server);
};

module.exports.fakeUser = fakeUser;
module.exports.credentials = credentials;
