var expect = require('chai').expect;
var server = require('./fixture/server');
var request = require('request');
var cheerio = require('cheerio');
var xmldom = require('xmldom');
var xmlhelper = require('./xmlhelper');

describe('samlp', function () {
  before(function (done) {
    server.start( { 
      audience: 'https://auth0-dev-ed.my.salesforce.com'
    },done);
  });
  
  after(function (done) {
    server.close(done);
  });

  describe('SAMLRequest on querystring', function () {
    var body, $, signedAssertion, attributes;

    before(function (done) {
      request.get({
        jar: request.jar(), 
        uri: 'http://localhost:5050/samlp?SAMLRequest=fZJbc6owFIX%2FCpN3EAEVMmIHEfDaqlCP%2BtKJELkUEkqCl%2F76Uj3O9JyHPmay9l4r%2BVb%2F6VLkwglXLKXEBG1JBgImIY1SEpvgNXBFHTwN%2BgwVeQmtmidkjT9qzLjQzBEGbxcmqCsCKWIpgwQVmEEeQt9azKEiybCsKKchzYFgMYYr3hjZlLC6wJWPq1Ma4tf13AQJ5yWDrVZO45RIDOWYHWkVYimkBRBGjWVKEL%2BlfEhDSjhlVEJNLvlb1%2FqOA4TJyARvynPH80qFFJPAdg%2Fh1fNnGVqpKO3OLkZonUfJ0Nu2Y2t6PdlVPj1RZxVlThywI8rihVH0MuksTQz3sx1Fm2xv5LO9nYSs5KXxfnm364%2FwfMDPWMqn182qHOqpjzR0dncsM6xO1Vs7h860HI97yrB7xHE9dt2loy%2FQu1prie%2FMcuNNL2i6nUdWp%2Fdnk3yekb7dXYhWjFjil%2Br2IC%2Bd%2FexlNF7wS77Zomvo7epFbCuyVx5tq3klYzWeEMYR4SZQ5LYqypqo6IGiQE2FmiKpencPhOXf%2Fx%2Bm5E71N1iHu4jBcRAsxeWLHwBh82hHIwD3LsCbefWjBL%2BvRQ%2FyYPCAd4MmRvgk4kgqrv8R77d%2B2Azup38LOPgC&RelayState=123'
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

    it.skip('should contain a valid signal assertion', function(){
      var isValid = xmlhelper.verifySignature(
                signedAssertion, 
                server.credentials.cert);
      expect(isValid).to.be.ok;
    });

    it('should have signature after issuer', function(){
      var doc = new xmldom.DOMParser().parseFromString(signedAssertion);
    
      var signature = doc.documentElement.getElementsByTagName('Signature');

      expect('saml:Issuer', signature[0].previousSibling.nodeName);
    });

    it('should use sha256 as default signature algorithm', function(){
      var algorithm = xmlhelper.getSignatureMethodAlgorithm(signedAssertion);
      expect(algorithm).to.equal('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
    });

    it('should use sha256 as default diigest algorithm', function(){
      var algorithm = xmlhelper.getDigestMethodAlgorithm(signedAssertion);
      expect(algorithm).to.equal('http://www.w3.org/2001/04/xmlenc#sha256');
    });


    it('should map every attributes from profile', function(){
      function validateAttribute(position, name, value) {
        expect(attributes[position].getAttribute('Name'))
          .to.equal(name);
        expect(attributes[position].firstChild.textContent)
          .to.equal(value);
      }

      validateAttribute(0, 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier', server.fakeUser.id);
      validateAttribute(1, 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',   server.fakeUser.emails[0].value);
      validateAttribute(2, 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',           server.fakeUser.displayName);
      validateAttribute(3, 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',      server.fakeUser.name.givenName);
      validateAttribute(4, 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',         server.fakeUser.name.familyName);
    });

    it('should contains the name identifier', function(){
      expect(xmlhelper.getNameIdentifier(signedAssertion).textContent)
        .to.equal(server.fakeUser.id);
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
        uri: 'http://localhost:5050/samlp?SAMLRequest=fZJbc6owFIX%2FCpN3EAEVMmIHEfDaqlCP%2BtKJELkUEkqCl%2F76Uj3O9JyHPmay9l4r%2BVb%2F6VLkwglXLKXEBG1JBgImIY1SEpvgNXBFHTwN%2BgwVeQmtmidkjT9qzLjQzBEGbxcmqCsCKWIpgwQVmEEeQt9azKEiybCsKKchzYFgMYYr3hjZlLC6wJWPq1Ma4tf13AQJ5yWDrVZO45RIDOWYHWkVYimkBRBGjWVKEL%2BlfEhDSjhlVEJNLvlb1%2FqOA4TJyARvynPH80qFFJPAdg%2Fh1fNnGVqpKO3OLkZonUfJ0Nu2Y2t6PdlVPj1RZxVlThywI8rihVH0MuksTQz3sx1Fm2xv5LO9nYSs5KXxfnm364%2FwfMDPWMqn182qHOqpjzR0dncsM6xO1Vs7h860HI97yrB7xHE9dt2loy%2FQu1prie%2FMcuNNL2i6nUdWp%2Fdnk3yekb7dXYhWjFjil%2Br2IC%2Bd%2FexlNF7wS77Zomvo7epFbCuyVx5tq3klYzWeEMYR4SZQ5LYqypqo6IGiQE2FmiKpencPhOXf%2Fx%2Bm5E71N1iHu4jBcRAsxeWLHwBh82hHIwD3LsCbefWjBL%2BvRQ%2FyYPCAd4MmRvgk4kgqrv8R77d%2B2Azup38LOPgC&RelayState=123'
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
        uri: 'http://localhost:5050/samlp?SAMLRequest=fZJbc6owFIX%2FCpN3EAEVMmIHEfDaqlCP%2BtKJELkUEkqCl%2F76Uj3O9JyHPmay9l4r%2BVb%2F6VLkwglXLKXEBG1JBgImIY1SEpvgNXBFHTwN%2BgwVeQmtmidkjT9qzLjQzBEGbxcmqCsCKWIpgwQVmEEeQt9azKEiybCsKKchzYFgMYYr3hjZlLC6wJWPq1Ma4tf13AQJ5yWDrVZO45RIDOWYHWkVYimkBRBGjWVKEL%2BlfEhDSjhlVEJNLvlb1%2FqOA4TJyARvynPH80qFFJPAdg%2Fh1fNnGVqpKO3OLkZonUfJ0Nu2Y2t6PdlVPj1RZxVlThywI8rihVH0MuksTQz3sx1Fm2xv5LO9nYSs5KXxfnm364%2FwfMDPWMqn182qHOqpjzR0dncsM6xO1Vs7h860HI97yrB7xHE9dt2loy%2FQu1prie%2FMcuNNL2i6nUdWp%2Fdnk3yekb7dXYhWjFjil%2Br2IC%2Bd%2FexlNF7wS77Zomvo7epFbCuyVx5tq3klYzWeEMYR4SZQ5LYqypqo6IGiQE2FmiKpencPhOXf%2Fx%2Bm5E71N1iHu4jBcRAsxeWLHwBh82hHIwD3LsCbefWjBL%2BvRQ%2FyYPCAd4MmRvgk4kgqrv8R77d%2B2Azup38LOPgC&RelayState=123'
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
        uri: 'http://localhost:5050/samlp?SAMLRequest=fZJbc6owFIX%2FCpN3EAEVMmIHEfDaqlCP%2BtKJELkUEkqCl%2F76Uj3O9JyHPmay9l4r%2BVb%2F6VLkwglXLKXEBG1JBgImIY1SEpvgNXBFHTwN%2BgwVeQmtmidkjT9qzLjQzBEGbxcmqCsCKWIpgwQVmEEeQt9azKEiybCsKKchzYFgMYYr3hjZlLC6wJWPq1Ma4tf13AQJ5yWDrVZO45RIDOWYHWkVYimkBRBGjWVKEL%2BlfEhDSjhlVEJNLvlb1%2FqOA4TJyARvynPH80qFFJPAdg%2Fh1fNnGVqpKO3OLkZonUfJ0Nu2Y2t6PdlVPj1RZxVlThywI8rihVH0MuksTQz3sx1Fm2xv5LO9nYSs5KXxfnm364%2FwfMDPWMqn182qHOqpjzR0dncsM6xO1Vs7h860HI97yrB7xHE9dt2loy%2FQu1prie%2FMcuNNL2i6nUdWp%2Fdnk3yekb7dXYhWjFjil%2Br2IC%2Bd%2FexlNF7wS77Zomvo7epFbCuyVx5tq3klYzWeEMYR4SZQ5LYqypqo6IGiQE2FmiKpencPhOXf%2Fx%2Bm5E71N1iHu4jBcRAsxeWLHwBh82hHIwD3LsCbefWjBL%2BvRQ%2FyYPCAd4MmRvgk4kgqrv8R77d%2B2Azup38LOPgC&RelayState=123'
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


});