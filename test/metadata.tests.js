var expect = require('chai').expect;
var server = require('./fixture/server');
var request = require('request');
var xmldom = require('@auth0/xmldom');

function certToPem (cert) {
  var pem = /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/g.exec(cert.toString());
  if (pem.length > 0) {
    return pem[1].replace(/[\n|\r\n]/g, '');
  }
  return null;
}

describe('samlp metadata', function () {
  before(function (done) {
    server.start(done);
  });

  after(function (done) {
    server.close(done);
  });

  describe('request to metadata', function (){
    var doc, content;
    before(function (done) {
      request.get({
        jar: request.jar(),
        uri: 'http://localhost:5050/samlp/FederationMetadata/2007-06/FederationMetadata.xml'
      }, function (err, response, b){
        if(err) return done(err);
        content = b;
        doc = new xmldom.DOMParser().parseFromString(b).documentElement;
        done();
      });
    });

    it('should have the redirect endpoint url', function(){
      expect(doc.getElementsByTagName('SingleSignOnService')[0].getAttribute('Binding'))
        .to.equal('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect');

      expect(doc.getElementsByTagName('SingleSignOnService')[0].getAttribute('Location'))
        .to.equal('http://localhost:5050/samlp/123');
    });

    it('should have the POST endpoint url', function(){
      expect(doc.getElementsByTagName('SingleSignOnService')[1].getAttribute('Binding'))
        .to.equal('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST');

      expect(doc.getElementsByTagName('SingleSignOnService')[1].getAttribute('Location'))
        .to.equal('http://localhost:5050/login/callback');
    });

    it('should have the logout endpoint url', function(){
      expect(doc.getElementsByTagName('SingleSignOnService')[0].getAttribute('Binding'))
        .to.equal('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect');

      expect(doc.getElementsByTagName('SingleLogoutService')[0].getAttribute('Location'))
        .to.equal('http://localhost:5050/logout');
    });

    it('should have the claim types', function(){
      expect(doc.getElementsByTagName('Attribute'))
        .to.not.be.empty;
    });

    it('should have the issuer', function(){
      expect(doc.getAttribute('entityID'))
        .to.equal('urn:fixture-test');
    });

    it('should have the pem', function(){
      expect(doc.getElementsByTagName('X509Certificate')[0].textContent)
        .to.equal(certToPem(server.credentials.cert));
    });

    it('should not contain blank line', function(){
      expect(content)
        .to.not.contain('\n\s*\n');
    });

  });

  describe('request to metadata with proxy', function () {
    var doc;
    before(function (done) {
      request.get({
        jar: request.jar(),
        uri: 'http://localhost:5050/samlp/FederationMetadata/2007-06/FederationMetadata.xml',
        headers: {
          'X-Forwarded-Host': 'myserver.com'
        }
      }, function (err, response, b) {
        if (err) return done(err);
        doc = new xmldom.DOMParser().parseFromString(b).documentElement;
        done();
      });
    });

    it('should have the redirect endpoint url with the forwarded host', function () {
      expect(doc.getElementsByTagName('SingleSignOnService')[0].getAttribute('Location'))
        .to.equal('http://myserver.com/samlp/123');
    });

    it('should have the POST endpoint url with the forwarded host', function () {
      expect(doc.getElementsByTagName('SingleSignOnService')[1].getAttribute('Location'))
        .to.equal('http://myserver.com/login/callback');
    });

    it('should have the logout endpoint url with the forwarded host', function () {
      expect(doc.getElementsByTagName('SingleLogoutService')[0].getAttribute('Location'))
        .to.equal('http://myserver.com/logout');
    });

  });
});