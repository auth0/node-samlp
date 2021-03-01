var expect = require('chai').expect;
var server = require('./fixture/server');
var request = require('request');
var cheerio = require('cheerio');
var xmldom = require('@auth0/xmldom');
var xmlhelper = require('./xmlhelper');
var zlib = require('zlib');
var encoder = require('../lib/encoders');
var fs = require('fs');
var path = require('path');

describe('samlp', function () {

  var urlEncodedSAMLRequest = 'fZJbc6owFIX%2FCpN3EAEVMmIHEfDaqlCP%2BtKJELkUEkqCl%2F76Uj3O9JyHPmay9l4r%2BVb%2F6VLkwglXLKXEBG1JBgImIY1SEpvgNXBFHTwN%2BgwVeQmtmidkjT9qzLjQzBEGbxcmqCsCKWIpgwQVmEEeQt9azKEiybCsKKchzYFgMYYr3hjZlLC6wJWPq1Ma4tf13AQJ5yWDrVZO45RIDOWYHWkVYimkBRBGjWVKEL%2BlfEhDSjhlVEJNLvlb1%2FqOA4TJyARvynPH80qFFJPAdg%2Fh1fNnGVqpKO3OLkZonUfJ0Nu2Y2t6PdlVPj1RZxVlThywI8rihVH0MuksTQz3sx1Fm2xv5LO9nYSs5KXxfnm364%2FwfMDPWMqn182qHOqpjzR0dncsM6xO1Vs7h860HI97yrB7xHE9dt2loy%2FQu1prie%2FMcuNNL2i6nUdWp%2Fdnk3yekb7dXYhWjFjil%2Br2IC%2Bd%2FexlNF7wS77Zomvo7epFbCuyVx5tq3klYzWeEMYR4SZQ5LYqypqo6IGiQE2FmiKpencPhOXf%2Fx%2Bm5E71N1iHu4jBcRAsxeWLHwBh82hHIwD3LsCbefWjBL%2BvRQ%2FyYPCAd4MmRvgk4kgqrv8R77d%2B2Azup38LOPgC';

  before(function (done) {
    server.start( {
      audience: 'https://auth0-dev-ed.my.salesforce.com'
    },done);
  });

  after(function (done) {
    server.close(done);
  });

  describe('Using custom profile mapper', function() {
    describe('when NameIdentifier is not found', function(){

      function ProfileMapper(user) {
        this.user = user;
      }
      ProfileMapper.prototype.getClaims = function () {
        return this.user;
      }
      ProfileMapper.prototype.getNameIdentifier = function (options) {
        return null;
      }

      before(function () {
        server.options = {
          profileMapper: function createProfileMapper(user) {
            return new ProfileMapper(user)
          }
        };
      });

      describe('and nameIdentifierProbes option is array of strings', function(){
        before(function () {
          server.options = Object.assign(server.options, {
            nameIdentifierProbes: ['id', 'email']
          });
        });

        it('should return error containing the list of probes', function(done){
          request.get({
            jar: request.jar(),
            uri: 'http://localhost:5050/samlp?SAMLRequest=' + urlEncodedSAMLRequest + '&RelayState=123'
          }, function (err, response){
            if(err) return done(err);
            expect(response.statusCode).to.equal(400);
            expect(response.body).to.equal('No attribute was found to generate the nameIdentifier. We tried with: id, email');
            done();
          });
        });
      });

      [ undefined, 1, 'a string', { value: 1 } ].forEach(function (testCaseValue) {
        describe('and nameIdentifierProbes option is not an array, type is ' + (typeof testCaseValue), function(){
          before(function () {
            server.options = Object.assign(server.options, {
              nameIdentifierProbes: testCaseValue
            });
          });

          it('should return error without probes', function(done){
            request.get({
              jar: request.jar(),
              uri: 'http://localhost:5050/samlp?SAMLRequest=' + urlEncodedSAMLRequest + '&RelayState=123'
            }, function (err, response){
              if(err) return done(err);
              expect(response.statusCode).to.equal(400);
              expect(response.body).to.equal('No attribute was found to generate the nameIdentifier. We tried with: ');
              done();
            });
          });
        });
      });
    });
  });

  describe('SAMLRequest on querystring', function () {
    var body, $, signedAssertion, attributes;

    before(function (done) {
      server.options = {};
      request.get({
        jar: request.jar(),
        uri: 'http://localhost:5050/samlp?SAMLRequest=' + urlEncodedSAMLRequest + '&RelayState=123'
      }, function (err, response, b){
        if(err) return done(err);
        expect(response.statusCode)
          .to.equal(200);

        body = b;
        $ = cheerio.load(body);
        var SAMLResponse = $('input[name="SAMLResponse"]').attr('value');
        var decoded = new Buffer(SAMLResponse, 'base64').toString();
        signedAssertion = /(<saml:Assertion.*<\/saml:Assertion>)/.exec(decoded)[1];
        attributes = xmlhelper.getAttributes(signedAssertion);
        done();
      });
    });

    it('should contain a form in the result', function(){
      expect(body).to.match(/<form/);
    });

    it('should contain the RelayState input', function () {
      expect($('input[name="RelayState"]').attr('value')).to.equal('123');
    });

    it('should contain a valid signal assertion', function(){
      var isValid = xmlhelper.verifySignature(
                signedAssertion,
                server.credentials.cert);
      expect(isValid).to.be.ok;
    });

    it('should have signature after issuer', function(){
      var doc = new xmldom.DOMParser().parseFromString(signedAssertion);

      var signature = doc.documentElement.getElementsByTagName('Signature');
      expect(signature[0].previousSibling.nodeName).to.equal('saml:Issuer');
    });

    it('should use sha256 as default signature algorithm', function(){
      var algorithm = xmlhelper.getSignatureMethodAlgorithm(signedAssertion);
      expect(algorithm).to.equal('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
    });

    it('should use sha256 as default digest algorithm', function(){
      var algorithm = xmlhelper.getDigestMethodAlgorithm(signedAssertion);
      expect(algorithm).to.equal('http://www.w3.org/2001/04/xmlenc#sha256');
    });

    it('should map every attributes from profile', function(){
      function validateAttribute(position, name, value, type, nameFormat) {

        expect(attributes[position].getAttribute('Name'))
          .to.equal(name);
        expect(attributes[position].getAttribute('NameFormat'))
        .to.equal(nameFormat);
        expect(attributes[position].firstChild.getAttribute('xsi:type'))
        .to.equal(type);
        expect(attributes[position].firstChild.textContent)
          .to.equal(value);
      }

      validateAttribute(0, 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier', String(server.fakeUser.id), 'xs:double', 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri');
      validateAttribute(1, 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',   server.fakeUser.emails[0].value, 'xs:string', 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri');
      validateAttribute(2, 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',           server.fakeUser.displayName, 'xs:string', 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri');
      validateAttribute(3, 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',      server.fakeUser.name.givenName, 'xs:string', 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri');
      validateAttribute(4, 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',        server.fakeUser.name.familyName, 'xs:string', 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri');
    });

    it('should contains the name identifier', function(){
      expect(xmlhelper.getNameIdentifier(signedAssertion).textContent)
        .to.equal(String(server.fakeUser.id));
    });

    it('should set nameidentifier format to urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified by default', function(){
      expect(xmlhelper.getNameIdentifier(signedAssertion).getAttribute('Format'))
        .to.equal('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified');
    });

    it('should contains the issuer', function(){
      expect(xmlhelper.getIssuer(signedAssertion))
        .to.equal('urn:fixture-test');
    });

    it('should contains the audiences', function(){
      expect(xmlhelper.getAudiences(signedAssertion)[0].textContent)
        .to.equal('https://auth0-dev-ed.my.salesforce.com');
    });

    it('should contain the callback', function () {
      expect($('form').attr('action')).to.equal('http://office.google.com');
    });

    it('should use the default authnContextClassRef', function () {
      expect(xmlhelper.getAuthnContextClassRef(signedAssertion).textContent)
        .to.equal('urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified');
    });
  });

  describe('SAMLRequest on querystring with a specific authnContextClassRef', function () {
    var body, $, signedAssertion, attributes;

    before(function (done) {
      server.options = { authnContextClassRef: "something" };
      request.get({
        jar: request.jar(),
        uri: 'http://localhost:5050/samlp?SAMLRequest=' + urlEncodedSAMLRequest + '&RelayState=123'
      }, function (err, response, b){
        if(err) return done(err);
        expect(response.statusCode)
          .to.equal(200);

        body = b;
        $ = cheerio.load(body);
        var SAMLResponse = $('input[name="SAMLResponse"]').attr('value');
        var decoded = new Buffer(SAMLResponse, 'base64').toString();
        signedAssertion = /(<saml:Assertion.*<\/saml:Assertion>)/.exec(decoded)[1];
        attributes = xmlhelper.getAttributes(signedAssertion);
        done();
      });
    });

    it('should use the expected authnContextClassRef', function () {
      expect(xmlhelper.getAuthnContextClassRef(signedAssertion).textContent)
        .to.equal('something');
    });
  });

  describe('when using an invalid audience', function () {
    before(function () {
      server.options = { getPostURL: function getPostURL (audience, samlRequestDom, req, callback) {
          // return a null post url
          callback(null, null);
        }
      };
    });

    it('should return error', function(done){
      request.get({
        jar: request.jar(),
        uri: 'http://localhost:5050/samlp?SAMLRequest=' + urlEncodedSAMLRequest + '&RelayState=123'
      }, function (err, response){
        if(err) return done(err);
        expect(response.statusCode)
          .to.equal(401);
        done();
      });
    });
  });

  describe('when using a different name identifier format', function () {
    var body, $, signedAssertion, attributes;

    before(function (done) {
      server.options = { nameIdentifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress' };
      request.get({
        jar: request.jar(),
        uri: 'http://localhost:5050/samlp?SAMLRequest=' + urlEncodedSAMLRequest + '&RelayState=123'
      }, function (err, response, b){
        if(err) return done(err);
        expect(response.statusCode)
          .to.equal(200);

        body = b;
        $ = cheerio.load(body);
        var SAMLResponse = $('input[name="SAMLResponse"]').attr('value');
        var decoded = new Buffer(SAMLResponse, 'base64').toString();
        signedAssertion = /(<saml:Assertion.*<\/saml:Assertion>)/.exec(decoded)[1];
        attributes = xmlhelper.getAttributes(signedAssertion);
        done();
      });
    });

    it('should override nameidentifier format', function(){
      expect(xmlhelper.getNameIdentifier(signedAssertion).getAttribute('Format'))
        .to.equal('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress');
    });
  });

  describe('when sending SAMLRequest ID ', function () {
    var body, $, signedAssertion, samlResponse;

    before(function (done) {
      // SAMLRequest =
      // <?xml version="1.0" encoding="UTF-8"?>
      // <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" AssertionConsumerServiceURL="https://acs"
      //        Destination="https://destination"
      //        ID="12345"
      //        IssueInstant="2013-04-28T22:43:42.386Z"
      //        ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0">
      //     <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://sp</saml:Issuer>
      //  </samlp:AuthnRequest>
      request.get({
        jar: request.jar(),
        uri: 'http://localhost:5050/samlp?SAMLRequest=fZBPb4MwDMW%2FSuQ7fxrYhCygYqumVeo0VOgOu2U0WpEgYXGo9vGXwdDaS2%2BO7fi990vX333HztJQq1UGKz8EJlWjj636zOBQP3kJrPOURN8NWIz2pPbya5RkmfunCKdBBqNRqAW1hEr0ktA2WBUvO%2BR%2BiIPRVje6A1YQSWOd0KNWNPbSVNKc20Ye9rsMTtYOhEEgGgK2cQqtEnYytUyO%2F01g241zy6P4zpVEo9wqskLZDHi4irww9nhSc45xhDH3o%2BT%2BHVj5Z%2BShVXO8W64%2F5iXC57ouvfK1qoG9LZjcAsxQcBI3FzRunxULAsh%2FY7lUNKTBxaV8fl3Dzn8A&RelayState=123'
      }, function (err, response, b){
        if(err) return done(err);
        expect(response.statusCode)
          .to.equal(200);

        body = b;
        $ = cheerio.load(body);
        var SAMLResponse = $('input[name="SAMLResponse"]').attr('value');
        samlResponse = new Buffer(SAMLResponse, 'base64').toString();
        signedAssertion = /(<saml:Assertion.*<\/saml:Assertion>)/.exec(samlResponse)[1];
        done();
      });
    });

    it('should send back the ID as InResponseTo', function(){
      expect(xmlhelper.getSubjectConfirmationData(signedAssertion).getAttribute('InResponseTo'))
        .to.equal('12345');
    });

    it('should send back the ID as InResponseTo', function(){
      var doc = new xmldom.DOMParser().parseFromString(samlResponse);
      expect(doc.documentElement.getAttribute('InResponseTo')).to.equal('12345');
    });
  });

  describe('when sending SAMLRequest without RelayState ', function () {
    var body, $, signedAssertion, samlResponse;

    before(function (done) {
      request.get({
        jar: request.jar(),
        uri: 'http://localhost:5050/samlp?SAMLRequest=fZBPb4MwDMW%2FSuQ7fxrYhCygYqumVeo0VOgOu2U0WpEgYXGo9vGXwdDaS2%2BO7fi990vX333HztJQq1UGKz8EJlWjj636zOBQP3kJrPOURN8NWIz2pPbya5RkmfunCKdBBqNRqAW1hEr0ktA2WBUvO%2BR%2BiIPRVje6A1YQSWOd0KNWNPbSVNKc20Ye9rsMTtYOhEEgGgK2cQqtEnYytUyO%2F01g241zy6P4zpVEo9wqskLZDHi4irww9nhSc45xhDH3o%2BT%2BHVj5Z%2BShVXO8W64%2F5iXC57ouvfK1qoG9LZjcAsxQcBI3FzRunxULAsh%2FY7lUNKTBxaV8fl3Dzn8A'
      }, function (err, response, b){
        if(err) return done(err);
        expect(response.statusCode)
          .to.equal(200);

        body = b;
        $ = cheerio.load(body);
        var SAMLResponse = $('input[name="SAMLResponse"]').attr('value');
        samlResponse = new Buffer(SAMLResponse, 'base64').toString();
        signedAssertion = /(<saml:Assertion.*<\/saml:Assertion>)/.exec(samlResponse)[1];
        done();
      });
    });

    it('should not throw an error', function(){
      expect(xmlhelper.getSubjectConfirmationData(signedAssertion).getAttribute('InResponseTo'))
        .to.equal('12345');
    });
  });

  describe('configured to accept SignedRequest', function(){
    before(function () {
      var cert = fs.readFileSync(path.join(__dirname, '/fixture/samlp.test-cert.pem'));
      server.options = {
        signingCert:  cert,
        thumbprints:  [encoder.thumbprint(cert)]
      };
    });

    describe('HTTP Redirect', function(){
      describe('when sending a not signed SAMLRequest', function(){
        var error;

        before(function (done) {
          request.get({
            jar: request.jar(),
            uri: 'http://localhost:5050/samlp?SAMLRequest=' + urlEncodedSAMLRequest + '&RelayState=123'
          }, function (err, response){
            if(err) return done(err);
            error = response.body;
            done();
          });
        });

        it('return signature missing error', function(){
          expect(error).to.equal("SAMLRequest message MUST be signed when using an asynchronous binding (POST or Redirect)");
        });
      });

      describe('when sending a signed SAMLRequest with ID that doesn\'t match', function(){
        var error;

        before(function (done) {
          var SAMLRequest = '<?xml version="1.0" encoding="UTF-8"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" AssertionConsumerServiceURL="https://acs" Destination="https://destination" ID="12345" IssueInstant="2013-04-28T22:43:42.386Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://sp</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx41d8ef22-e612-8c50-9960-1b16f15741b3"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>yJN6cXUwQxTmMEsPesBP2NkqYFI=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>g5eM9yPnKsmmE/Kh2qS7nfK8HoF6yHrAdNQxh70kh8pRI4KaNbYNOL9sF8F57Yd+jO6iNga8nnbwhbATKGXIZOJJSugXGAMRyZsj/rqngwTJk5KmujbqouR1SLFsbo7Iuwze933EgefBbAE4JRI7V2aD9YgmB3socPqAi2Qf97E=</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQQFADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcwMDI5MjdaFw0xNTA3MTcwMDI5MjdaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7vU/6R/OBA6BKsZH4L2bIQ2cqBO7/aMfPjUPJPSn59d/f0aRqSC58YYrPuQODydUABiCknOn9yV0fEYm4bNvfjroTEd8bDlqo5oAXAUAI8XHPppJNz7pxbhZW0u35q45PJzGM9nCv9bglDQYJLby1ZUdHsSiDIpMbGgf/ZrxqawIDAQABo1AwTjAdBgNVHQ4EFgQU3s2NEpYx7wH6bq7xJFKa46jBDf4wHwYDVR0jBBgwFoAU3s2NEpYx7wH6bq7xJFKa46jBDf4wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQQFAAOBgQCPsNO2FG+zmk5miXEswAs30E14rBJpe/64FBpM1rPzOleexvMgZlr0/smF3P5TWb7H8Fy5kEiByxMjaQmml/nQx6qgVVzdhaTANpIE1ywEzVJlhdvw4hmRuEKYqTaFMLez0sRL79LUeDxPWw7Mj9FkpRYT+kAGiFomHop1nErV6Q==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></samlp:AuthnRequest>';

          request.get({
            jar: request.jar(),
            uri: 'http://localhost:5050/samlp',
            qs: {
              RelayState: '123',
              SAMLRequest: new Buffer(SAMLRequest).toString('base64')
            }
          }, function (err, response){
            if(err) return done(err);
            error = response.body;
            done();
          });
        });

        it('should return signature check errors', function(){
          expect(error).to.equal('Signature check errors: invalid signature: the signature refernces an element with uri #pfx41d8ef22-e612-8c50-9960-1b16f15741b3 but could not find such element in the xml');
        });
      });

      describe('when sending a invalid signed SAMLRequest', function(){
        var error;

        before(function (done) {
          var SAMLRequest = '<?xml version="1.0" encoding="UTF-8"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="pfx41d8ef22-e612-8c50-9960-1b16f15741b3" AssertionConsumerServiceURL="https://acs" Destination="https://destination" IssueInstant="2013-04-28T22:43:42.386Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://sp</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx41d8ef22-e612-8c50-9960-1b16f15741b3"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>yJN6cXUwQxTmMEsPesBP2NkqYFI=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>g5eM9yPnKsmmE/Kh2qS7nfK8HoF6yHrAdNQxh70kh8pRI4KaNbYNOL9sF8F57Yd+jO6iNga8nnbwhbATKGXIZOJJSugXGAMRyZsj/rqngwTJk5KmujbqouR1SLFsbo7Iuwze933EgefBbAE4JRI7V2aD9YgmB3socPqAi2Qf97E=</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQQFADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcwMDI5MjdaFw0xNTA3MTcwMDI5MjdaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7vU/6R/OBA6BKsZH4L2bIQ2cqBO7/aMfPjUPJPSn59d/f0aRqSC58YYrPuQODydUABiCknOn9yV0fEYm4bNvfjroTEd8bDlqo5oAXAUAI8XHPppJNz7pxbhZW0u35q45PJzGM9nCv9bglDQYJLby1ZUdHsSiDIpMbGgf/ZrxqawIDAQABo1AwTjAdBgNVHQ4EFgQU3s2NEpYx7wH6bq7xJFKa46jBDf4wHwYDVR0jBBgwFoAU3s2NEpYx7wH6bq7xJFKa46jBDf4wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQQFAAOBgQCPsNO2FG+zmk5miXEswAs30E14rBJpe/64FBpM1rPzOleexvMgZlr0/smF3P5TWb7H8Fy5kEiByxMjaQmml/nQx6qgVVzdhaTANpIE1ywEzVJlhdvw4hmRuEKYqTaFMLez0sRL79LUeDxPWw7Mj9FkpRYT+kAGiFomHop1nErV6Q==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></samlp:AuthnRequest>';

          request.get({
            jar: request.jar(),
            uri: 'http://localhost:5050/samlp',
            qs: {
              RelayState: '123',
              SAMLRequest: new Buffer(SAMLRequest).toString('base64')
            }
          }, function (err, response){
            if(err) return done(err);
            error = response.body;
            done();
          });
        });

        it('should return signature check errors', function(){
          expect(error).to.equal('Signature check errors: invalid signature: for uri #pfx41d8ef22-e612-8c50-9960-1b16f15741b3 calculated digest is CNSDTrlQsaLjOFN4js626JZBqP0= but the xml to validate supplies digest yJN6cXUwQxTmMEsPesBP2NkqYFI=');
        });
      });

      describe('when sending a valid signed SAMLRequest but wrong certificate', function(){
        var error;

        before(function (done) {
          var SAMLRequest = '<?xml version="1.0" encoding="UTF-8"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="pfx41d8ef22-e612-8c50-9960-1b16f15741b3" AssertionConsumerServiceURL="https://acs" Destination="https://destination" IssueInstant="2013-04-28T22:43:42.386Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://sp</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfx41d8ef22-e612-8c50-9960-1b16f15741b3"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>CNSDTrlQsaLjOFN4js626JZBqP0=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>g5eM9yPnKsmmE/Kh2qS7nfK8HoF6yHrAdNQxh70kh8pRI4KaNbYNOL9sF8F57Yd+jO6iNga8nnbwhbATKGXIZOJJSugXGAMRyZsj/rqngwTJk5KmujbqouR1SLFsbo7Iuwze933EgefBbAE4JRI7V2aD9YgmB3socPqAi2Qf97E=</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQQFADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcwMDI5MjdaFw0xNTA3MTcwMDI5MjdaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7vU/6R/OBA6BKsZH4L2bIQ2cqBO7/aMfPjUPJPSn59d/f0aRqSC58YYrPuQODydUABiCknOn9yV0fEYm4bNvfjroTEd8bDlqo5oAXAUAI8XHPppJNz7pxbhZW0u35q45PJzGM9nCv9bglDQYJLby1ZUdHsSiDIpMbGgf/ZrxqawIDAQABo1AwTjAdBgNVHQ4EFgQU3s2NEpYx7wH6bq7xJFKa46jBDf4wHwYDVR0jBBgwFoAU3s2NEpYx7wH6bq7xJFKa46jBDf4wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQQFAAOBgQCPsNO2FG+zmk5miXEswAs30E14rBJpe/64FBpM1rPzOleexvMgZlr0/smF3P5TWb7H8Fy5kEiByxMjaQmml/nQx6qgVVzdhaTANpIE1ywEzVJlhdvw4hmRuEKYqTaFMLez0sRL79LUeDxPWw7Mj9FkpRYT+kAGiFomHop1nErV6Q==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></samlp:AuthnRequest>';

          request.get({
            jar: request.jar(),
            uri: 'http://localhost:5050/samlp',
            qs: {
              RelayState: '123',
              SAMLRequest: new Buffer(SAMLRequest).toString('base64')
            }
          }, function (err, response){
            if(err) return done(err);
            error = response.body;
            done();
          });
        });

        it('should return invalid signature', function(){
          expect(error).to.equal('Signature check errors: invalid signature: the signature value g5eM9yPnKsmmE/Kh2qS7nfK8HoF6yHrAdNQxh70kh8pRI4KaNbYNOL9sF8F57Yd+jO6iNga8nnbwhbATKGXIZOJJSugXGAMRyZsj/rqngwTJk5KmujbqouR1SLFsbo7Iuwze933EgefBbAE4JRI7V2aD9YgmB3socPqAi2Qf97E= is incorrect');
        });
      });

      describe('when sending a valid signed SAMLRequest with embeded cert', function(){
        var body, samlResponse, signedAssertion, $;

        before(function (done) {
          var samlRequest = 'PHNhbWxwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiBEZXN0aW5hdGlvbj0iaHR0cDovL2xvY2FsaG9zdDo1MDUxL3NhbWxwIiBJRD0iX2NlZWFlZjQwMjAxNmMxMGRmM2FiIiBJc3N1ZUluc3RhbnQ9IjIwMTYtMTEtMDdUMTA6MTU6MjlaIiBQcm90b2NvbEJpbmRpbmc9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpiaW5kaW5nczpIVFRQLVBPU1QiIFZlcnNpb249IjIuMCI+PFNpZ25hdHVyZSB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+PFNpZ25lZEluZm8+PENhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxkc2lnLW1vcmUjcnNhLXNoYTI1NiIvPjxSZWZlcmVuY2UgVVJJPSIjX2NlZWFlZjQwMjAxNmMxMGRmM2FiIj48VHJhbnNmb3Jtcz48VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PC9UcmFuc2Zvcm1zPjxEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiLz48RGlnZXN0VmFsdWU+RzQ2eG9DbmhiZWUzRjB0cW0yWklMamkvTHRmZEJQNWdnTml3emcxOEVxUT08L0RpZ2VzdFZhbHVlPjwvUmVmZXJlbmNlPjwvU2lnbmVkSW5mbz48U2lnbmF0dXJlVmFsdWU+VzVzS3FsOHRTYVJVZm9HSUJsYXVXbmR6WXNsWmRxc3BSQmlsa2pGSTlXVkxrTXlmWWZCckJza1VLMzJDckdDb3JZc0FkZUEyYW9rSUYwL3RRVUNISXdHcmF0cWZGVDZiVVNQdVBoT2JsZ3UzcWpmODI2Tm5hNzl1S2I4OXdDQnoyRzF0US9JSEVPZlJUNjcwZ25oZ0NiTzV4VlFZZnQvbmxzU281QW1sbkx6QXZsZW5JNFhZT3JZd3Q4bkJ6MGVnM3NTUlJmVWt5UGx1TDE2ck84bFdSdWVqenp6R250SjFiZDM5QzBZc0k1SjlIOWxMTm9LTXh1MFJwU1B2Z0llaGhESGJoc24zRVlsd25OcldKMUdINlhIakxKdmV1dGJuVWp2V0NEZ2U3Wi9XRUc2V2Eya01hMGFYM0VJa2lNYk0zeDFFZzd3bk1jMGM4OU9TU1FCNFF3PT08L1NpZ25hdHVyZVZhbHVlPjxLZXlJbmZvPjxYNTA5RGF0YT48WDUwOUNlcnRpZmljYXRlPk1JSUR0VENDQXAyZ0F3SUJBZ0lKQU1LUi9Oc3lmY2F6TUEwR0NTcUdTSWIzRFFFQkJRVUFNRVV4Q3pBSkJnTlZCQVlUQWtGVk1STXdFUVlEVlFRSUV3cFRiMjFsTFZOMFlYUmxNU0V3SHdZRFZRUUtFeGhKYm5SbGNtNWxkQ0JYYVdSbmFYUnpJRkIwZVNCTWRHUXdIaGNOTVRJeE1URXlNak0wTXpReFdoY05NVFl4TWpJeE1qTTBNelF4V2pCRk1Rc3dDUVlEVlFRR0V3SkJWVEVUTUJFR0ExVUVDQk1LVTI5dFpTMVRkR0YwWlRFaE1COEdBMVVFQ2hNWVNXNTBaWEp1WlhRZ1YybGtaMmwwY3lCUWRIa2dUSFJrTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF2dEg0d0tMWWxJWFpsZllRRkp0WFpWQzNmRDhYTWFyend2Yi9mSFV5SjZOdk5TdE4rSDdHSHAzL1FoWmJTYVJ5cUs1aHU1eFh0RkxnbkkwUUc4b0UxTmxYYmN6akg0NUxlSFdoUElkYzJ1SFNwelhpYzc4a091Z01ZMXZuZzRKMTBQRjYrVDJGTmFpdjBpWGVJUXE5eGJ3d1BZcGZsVmlReUpuekdDSVo3VkdhbjZHYlJLenlUS2NCNTh5eDI0cEpxK0N2aUxYRVk1MlRJVzFsNWltY2pHdkx0bENwMXphOXFCWmE0WEdvVnFIaTFrUlhrZERTSHR5NmxaV2ozS3hvUnZUYmlhQkNIKzc1VTdyaWZTNmZSOWxxaldFNTdiQ0dvejcrQkJ1OVltUEt0STFLa3lIRnFXcHhhSmMvQUtmOXhnZytVdW1lcVZjaXJVbUFzSEpyTXdJREFRQUJvNEduTUlHa01CMEdBMVVkRGdRV0JCVHM4M25rTHRvWEZsbUJVdHMzRUl4Y1Z2a3ZjakIxQmdOVkhTTUViakJzZ0JUczgzbmtMdG9YRmxtQlV0czNFSXhjVnZrdmNxRkpwRWN3UlRFTE1Ba0dBMVVFQmhNQ1FWVXhFekFSQmdOVkJBZ1RDbE52YldVdFUzUmhkR1V4SVRBZkJnTlZCQW9UR0VsdWRHVnlibVYwSUZkcFpHZHBkSE1nVUhSNUlFeDBaSUlKQU1LUi9Oc3lmY2F6TUF3R0ExVWRFd1FGTUFNQkFmOHdEUVlKS29aSWh2Y05BUUVGQlFBRGdnRUJBQnc3dy81azRkNWRWRGdkL09PT21YZGFhQ0lLdnQ3ZDNudGx2MVNTdkFvS1Q4ZDhsdDk3RG01UnJtZWZCSTEzSTJ5aXZaZzViZlRnZTQrdkFWNlZkTEZkV2VGcDFiL0ZPWmtZVXY2QThvNUhXME9XUVlWWDI2eklxQmNHMlFybTNyZWlTbDVCTHZwajFXU3BDc1l2czVrYU80dkZwTWFrL0lDZ2RaRCtyeHd4ZjhWYi82Zm50S3l3V1NMZ3dLSDNtSitaMGtSbHBxMWcxb2llaU9tMS9ncFozNXMwWXVvclhaYmE5cHRmTENZU2dnZy9xYzNkM2QwdGJIcGxLWWt3Rm03ZjVPUkdIRFNENVNKbStnSTdSUEUrNGJPOHE3OVJQQWZiRzFVR3VKMGIvb2lnYWdjaUhoSnA4NTFTUVJZZjNKdU5TYzE3Qm5LMkw1SUV0empxcitRPTwvWDUwOUNlcnRpZmljYXRlPjwvWDUwOURhdGE+PC9LZXlJbmZvPjwvU2lnbmF0dXJlPjxzYW1sOklzc3VlciB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj5odHRwczovL2F1dGgwLWRldi1lZC5teS5zYWxlc2ZvcmNlLmNvbTwvc2FtbDpJc3N1ZXI+PC9zYW1scDpBdXRoblJlcXVlc3Q+';
          request.get({
            jar: request.jar(),
            uri: 'http://localhost:5050/samlp',
            qs: {
              RelayState: '123',
              SAMLRequest: samlRequest
            }
          }, function (err, response, b){
            if(err) return done(err);
            expect(response.statusCode)
              .to.equal(200);

            body = b;
            $ = cheerio.load(body);
            var SAMLResponse = $('input[name="SAMLResponse"]').attr('value');
            samlResponse = new Buffer(SAMLResponse, 'base64').toString();
            signedAssertion = /(<saml:Assertion.*<\/saml:Assertion>)/.exec(samlResponse)[1];
            done();
          });
        });

        it('should return invalid signature', function(){
          expect(signedAssertion).to.be.ok;
        });
      });
    });

    describe('HTTP Redirect - Inflated', function(){
      describe('when not sending Signature', function(){
        var error;

        before(function (done) {
          var SAMLRequest = '<?xml version="1.0" encoding="UTF-8"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" AssertionConsumerServiceURL="https://acs" Destination="https://destination" ID="12345" IssueInstant="2013-04-28T22:43:42.386Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://sp</saml:Issuer></samlp:AuthnRequest>';

          zlib.deflateRaw(new Buffer(SAMLRequest), function (err, buffer) {
            if (err) return done(err);

            request.get({
              jar: request.jar(),
              uri: 'http://localhost:5050/samlp',
              qs: {
                RelayState: '123',
                SAMLRequest: buffer.toString('base64')
              }
            }, function (err, response){
              if(err) return done(err);
              error = response.body;
              done();
            });
          });
        });

        it('should return signature check errors', function(){
          expect(error).to.equal("SAMLRequest message MUST be signed when using an asynchronous binding (POST or Redirect)");
        });
      });

      describe('when not sending SigAlg', function(){
        var error;

        before(function (done) {
          var SAMLRequest = '<?xml version="1.0" encoding="UTF-8"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" AssertionConsumerServiceURL="https://acs" Destination="https://destination" ID="12345" IssueInstant="2013-04-28T22:43:42.386Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://sp</saml:Issuer></samlp:AuthnRequest>';

          zlib.deflateRaw(new Buffer(SAMLRequest), function (err, buffer) {
            if (err) return done(err);

            request.get({
              jar: request.jar(),
              uri: 'http://localhost:5050/samlp',
              qs: {
                RelayState: '123',
                SAMLRequest: buffer.toString('base64'),
                Signature: '123123'
              }
            }, function (err, response){
              if(err) return done(err);
              error = response.body;
              done();
            });
          });
        });

        it('should return missing Signature Algorithm message', function(){
          expect(error).to.equal("Signature Algorithm is missing");
        });
      });

      describe('when sending invalid Sigature Algorithm', function(){
        var error;

        before(function (done) {
          var SAMLRequest = '<?xml version="1.0" encoding="UTF-8"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" AssertionConsumerServiceURL="https://acs" Destination="https://destination" ID="12345" IssueInstant="2013-04-28T22:43:42.386Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://sp</saml:Issuer></samlp:AuthnRequest>';

          zlib.deflateRaw(new Buffer(SAMLRequest), function (err, buffer) {
            if (err) return done(err);

            request.get({
              jar: request.jar(),
              uri: 'http://localhost:5050/samlp',
              qs: {
                RelayState: '123',
                SAMLRequest: buffer.toString('base64'),
                Signature: '123123',
                SigAlg: '123'
              }
            }, function (err, response){
              if(err) return done(err);
              error = response.body;
              done();
            });
          });
        });

        it('should return invalid Signature Algorithm message', function(){
          expect(error).to.equal("Invalid signature algorithm. Supported algorithms are http://www.w3.org/2001/04/xmldsig-more#rsa-sha1 and http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        });
      });

      describe('when valid algorithm and invalid signature', function(){
        var error;

        before(function (done) {
          var SAMLRequest = '<?xml version="1.0" encoding="UTF-8"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" AssertionConsumerServiceURL="https://acs" Destination="https://destination" ID="12345" IssueInstant="2013-04-28T22:43:42.386Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://sp</saml:Issuer></samlp:AuthnRequest>';

          zlib.deflateRaw(new Buffer(SAMLRequest), function (err, buffer) {
            if (err) return done(err);

            request.get({
              jar: request.jar(),
              uri: 'http://localhost:5050/samlp',
              qs: {
                RelayState: '123',
                SAMLRequest: buffer.toString('base64'),
                Signature: '123123',
                SigAlg: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
              }
            }, function (err, response){
              if(err) return done(err);
              error = response.body;
              done();
            });
          });
        });

        it('should return missing signature check errors', function(){
          expect(error).to.equal("Signature check errors: The signature provided (123123) does not match the one calculated");
        });
      });

      describe('when valid signature and algorithm', function(){
        var body, samlResponse, signedAssertion, $;

        before(function (done) {
          var SAMLRequest = '<?xml version="1.0" encoding="UTF-8"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" AssertionConsumerServiceURL="https://acs" Destination="https://destination" ID="12345" IssueInstant="2013-04-28T22:43:42.386Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://sp</saml:Issuer></samlp:AuthnRequest>';

          zlib.deflateRaw(new Buffer(SAMLRequest), function (err, buffer) {
            if (err) return done(err);

            request.get({
              jar: request.jar(),
              uri: 'http://localhost:5050/samlp',
              qs: {
                RelayState: '123',
                SAMLRequest: buffer.toString('base64'),
                Signature: 'HaX739zOyRn4PR2pi1Bud05rHbPGfppz5x5crr2EuOzLbfNuvLeK//ZCNsC/R/8B4CWe2SYYCYJ6UhBRvhCx8G7H92TIw8TjbsTfAWemp6mJh+zBqaI2It8sFZMYntsbd0jfBo4CbuM8872cNQkdedV5V56gaErjBA8z3HoyTWpQi9nH2fjtmDDfoQmoVum5q+vgbm103qxjH0j/gR+OXi5Rne8ijMLhhXgt9EdLmN8OS6l1LRUPe3XDLz6ZKbo9T2k6GR1x+w6bN18JOdeCwDn+nx4fmPbGGrcz/DT/3mTL5MY7TeRDz8rGSCZ5+yDNtmgQ9Nv2O//joonmRBkF6Q==',
                SigAlg: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
              }
            }, function (err, response, b){
                if(err) return done(err);

                expect(response.statusCode)
                  .to.equal(200);

                body = b;
                $ = cheerio.load(body);
                var SAMLResponse = $('input[name="SAMLResponse"]').attr('value');
                samlResponse = new Buffer(SAMLResponse, 'base64').toString();
                signedAssertion = /(<saml:Assertion.*<\/saml:Assertion>)/.exec(samlResponse)[1];
                done();
            });
          });
        });

        it('should return assertion', function(){
          expect(signedAssertion).to.be.ok;
        });
      });
    });
  });

  describe('response signing', function () {

    function doRawSAMLRequest(testResponse) {
      request.get({
        jar: request.jar(),
        uri: 'http://localhost:5050/samlp?SAMLRequest=fZBPb4MwDMW%2FSuQ7fxrYhCygYqumVeo0VOgOu2U0WpEgYXGo9vGXwdDaS2%2BO7fi990vX333HztJQq1UGKz8EJlWjj636zOBQP3kJrPOURN8NWIz2pPbya5RkmfunCKdBBqNRqAW1hEr0ktA2WBUvO%2BR%2BiIPRVje6A1YQSWOd0KNWNPbSVNKc20Ye9rsMTtYOhEEgGgK2cQqtEnYytUyO%2F01g241zy6P4zpVEo9wqskLZDHi4irww9nhSc45xhDH3o%2BT%2BHVj5Z%2BShVXO8W64%2F5iXC57ouvfK1qoG9LZjcAsxQcBI3FzRunxULAsh%2FY7lUNKTBxaV8fl3Dzn8A&RelayState=123'
      }, function (err, response) {
        expect(err).to.equal(null);

        testResponse(response);
      });
    }

    function doSAMLRequest(testSamlResponse) {
      doRawSAMLRequest(function(response) {
        expect(response.statusCode).to.equal(200);

        var SAMLResponse = cheerio.load(response.body)('input[name="SAMLResponse"]').attr('value');
        var samlResponse = new Buffer(SAMLResponse, 'base64').toString();
        var doc = new xmldom.DOMParser().parseFromString(samlResponse);
        testSamlResponse(doc);
      });
    }

    describe('signResponse=true and signAssertion=true', function () {
      before(function () {
        server.options = { signatureNamespacePrefix: 'ds', signResponse: true, signAssertion: true };
      });

      it('should sign the response and the assertion', function (done) {
        doSAMLRequest(function (samlResponse) {
          var signatures = samlResponse.documentElement.getElementsByTagName('ds:Signature');
          expect(signatures).to.have.lengthOf(2);
          expect(signatures[0].parentNode.nodeName).to.equal('samlp:Response');
          expect(signatures[1].parentNode.nodeName).to.equal('saml:Assertion');
          done();
        });
      });

      describe('when invalid signing key is used', function () {
        before(function () {
          server.options.key = 'invalid_signing_key';
        });

        it('should return an error', function (done) {
          doRawSAMLRequest(function (response) {
            expect(response.statusCode).to.equal(400);
            expect(response.body).to.match(/error:\w+:PEM routines:\w+:no start line/);
            done();
          });
        });
      });
    });

    describe('signResponse=true and signAssertion is undefined', function () {
      before(function () {
        server.options = { signatureNamespacePrefix: 'ds', signResponse: true }; // for backward compatibility
      });

      it('should sign the response and the assertion', function (done) {
        doSAMLRequest(function (samlResponse) {
          var signatures = samlResponse.documentElement.getElementsByTagName('ds:Signature');
          expect(signatures).to.have.lengthOf(2);
          expect(signatures[0].parentNode.nodeName).to.equal('samlp:Response');
          expect(signatures[1].parentNode.nodeName).to.equal('saml:Assertion');
          done();
        });
      });
    });

    describe('signResponse=true and signAssertion=false', function () {
      before(function () {
        server.options = { signatureNamespacePrefix: 'ds', signResponse: true, signAssertion: false };
      });

      it('should sign the response and not the assertion', function (done) {
        doSAMLRequest(function (samlResponse) {
          var signatures = samlResponse.documentElement.getElementsByTagName('ds:Signature');
          expect(signatures).to.have.lengthOf(1);
          expect(signatures[0].parentNode.nodeName).to.equal('samlp:Response');
          done();
        });
      });

      describe('when invalid signing key is used', function () {
        before(function () {
          server.options.key = 'invalid_signing_key';
        });

        after(function () {
          delete server.options.key;
        });

        it('should return an error', function (done) {
          doRawSAMLRequest(function (response) {
            expect(response.statusCode).to.equal(400);
            expect(response.body).to.match(/error:\w+:PEM routines:\w+:no start line/);
            done();
          });
        });
      });
    });

    describe('signResponse=false and signAssertion=true', function () {
      before(function () {
        server.options = { signatureNamespacePrefix: 'ds', signResponse: false, signAssertion: true };
      });

      it('should sign the assertion and not the response', function (done) {
        doSAMLRequest(function (samlResponse) {
          var signatures = samlResponse.documentElement.getElementsByTagName('ds:Signature');
          expect(signatures).to.have.lengthOf(1);
          expect(signatures[0].parentNode.nodeName).to.equal('saml:Assertion');
          done();
        });
      });
    });

    describe('signResponse and signAssertion are both undefined', function () {
      before(function () {
        server.options = { signatureNamespacePrefix: 'ds' };
      });

      it('should sign the assertion and not the response', function (done) {
        doSAMLRequest(function (samlResponse) {
          var signatures = samlResponse.documentElement.getElementsByTagName('ds:Signature');
          expect(signatures).to.have.lengthOf(1);
          expect(signatures[0].parentNode.nodeName).to.equal('saml:Assertion');
          done();
        });
      });
    });
  });

  describe('configured signature signatureNamespacePrefix', function(){
    describe('signResponse = true', function(){
      var body, $, signedAssertion, samlResponse;

      before(function (done) {
        server.options = {  signatureNamespacePrefix: 'ds' , signResponse : true };
        request.get({
          jar: request.jar(),
          uri: 'http://localhost:5050/samlp?SAMLRequest=fZBPb4MwDMW%2FSuQ7fxrYhCygYqumVeo0VOgOu2U0WpEgYXGo9vGXwdDaS2%2BO7fi990vX333HztJQq1UGKz8EJlWjj636zOBQP3kJrPOURN8NWIz2pPbya5RkmfunCKdBBqNRqAW1hEr0ktA2WBUvO%2BR%2BiIPRVje6A1YQSWOd0KNWNPbSVNKc20Ye9rsMTtYOhEEgGgK2cQqtEnYytUyO%2F01g241zy6P4zpVEo9wqskLZDHi4irww9nhSc45xhDH3o%2BT%2BHVj5Z%2BShVXO8W64%2F5iXC57ouvfK1qoG9LZjcAsxQcBI3FzRunxULAsh%2FY7lUNKTBxaV8fl3Dzn8A&RelayState=123'
        }, function (err, response, b){
          if(err) return done(err);
          expect(response.statusCode)
            .to.equal(200);

          body = b;
          $ = cheerio.load(body);
          var SAMLResponse = $('input[name="SAMLResponse"]').attr('value');
          samlResponse = new Buffer(SAMLResponse, 'base64').toString();
          signedAssertion = /(<saml:Assertion.*<\/saml:Assertion>)/.exec(samlResponse)[1];
          done();
        });
      });

      it('should return signature with the specified signatureNamespacePrefix inside the response', function(){
        var doc = new xmldom.DOMParser().parseFromString(samlResponse);
        var signature = doc.documentElement.getElementsByTagName('ds:Signature');
        expect(signature[0].parentNode.nodeName).to.equal('samlp:Response');
      });
    });

    describe('signResponse = false', function(){
      var body, $, signedAssertion, samlResponse;

      before(function (done) {
        server.options = {  signatureNamespacePrefix: 'ds' , signResponse : false };
        request.get({
          jar: request.jar(),
          uri: 'http://localhost:5050/samlp?SAMLRequest=fZBPb4MwDMW%2FSuQ7fxrYhCygYqumVeo0VOgOu2U0WpEgYXGo9vGXwdDaS2%2BO7fi990vX333HztJQq1UGKz8EJlWjj636zOBQP3kJrPOURN8NWIz2pPbya5RkmfunCKdBBqNRqAW1hEr0ktA2WBUvO%2BR%2BiIPRVje6A1YQSWOd0KNWNPbSVNKc20Ye9rsMTtYOhEEgGgK2cQqtEnYytUyO%2F01g241zy6P4zpVEo9wqskLZDHi4irww9nhSc45xhDH3o%2BT%2BHVj5Z%2BShVXO8W64%2F5iXC57ouvfK1qoG9LZjcAsxQcBI3FzRunxULAsh%2FY7lUNKTBxaV8fl3Dzn8A&RelayState=123'
        }, function (err, response, b){
          if(err) return done(err);
          expect(response.statusCode)
            .to.equal(200);

          body = b;
          $ = cheerio.load(body);
          var SAMLResponse = $('input[name="SAMLResponse"]').attr('value');
          samlResponse = new Buffer(SAMLResponse, 'base64').toString();
          signedAssertion = /(<saml:Assertion.*<\/saml:Assertion>)/.exec(samlResponse)[1];
          done();
        });
      });

      it('should return signature with the specified signatureNamespacePrefix inside the assertion', function(){
        var doc = new xmldom.DOMParser().parseFromString(signedAssertion);
        var signature = doc.documentElement.getElementsByTagName('ds:Signature');
        expect(signature[0].parentNode.nodeName).to.equal('saml:Assertion');
      });
    });

    describe('invalid signatureNamespacePrefix', function(){
      var body, $, signedAssertion, samlResponse;

      before(function (done) {
        server.options = {  signatureNamespacePrefix: 123 , signResponse : false };
        request.get({
          jar: request.jar(),
          uri: 'http://localhost:5050/samlp?SAMLRequest=fZBPb4MwDMW%2FSuQ7fxrYhCygYqumVeo0VOgOu2U0WpEgYXGo9vGXwdDaS2%2BO7fi990vX333HztJQq1UGKz8EJlWjj636zOBQP3kJrPOURN8NWIz2pPbya5RkmfunCKdBBqNRqAW1hEr0ktA2WBUvO%2BR%2BiIPRVje6A1YQSWOd0KNWNPbSVNKc20Ye9rsMTtYOhEEgGgK2cQqtEnYytUyO%2F01g241zy6P4zpVEo9wqskLZDHi4irww9nhSc45xhDH3o%2BT%2BHVj5Z%2BShVXO8W64%2F5iXC57ouvfK1qoG9LZjcAsxQcBI3FzRunxULAsh%2FY7lUNKTBxaV8fl3Dzn8A&RelayState=123'
        }, function (err, response, b){
          if(err) return done(err);
          expect(response.statusCode)
            .to.equal(200);

          body = b;
          $ = cheerio.load(body);
          var SAMLResponse = $('input[name="SAMLResponse"]').attr('value');
          samlResponse = new Buffer(SAMLResponse, 'base64').toString();
          signedAssertion = /(<saml:Assertion.*<\/saml:Assertion>)/.exec(samlResponse)[1];
          done();
        });
      });

      it('should return signature without signatureNamespacePrefix inside the assertion', function(){
        var doc = new xmldom.DOMParser().parseFromString(signedAssertion);
        var signature = doc.documentElement.getElementsByTagName('Signature');
        expect(signature[0].parentNode.nodeName).to.equal('saml:Assertion');
      });
    });
  });
});
