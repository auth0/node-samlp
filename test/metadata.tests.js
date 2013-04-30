var expect = require('chai').expect;
var server = require('./fixture/server');
var request = require('request');
var xmldom = require('xmldom');

function certToPem (cert) {
  var pem = /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/g.exec(cert.toString());
  if (pem.length > 0) {
    return pem[1].replace(/[\n|\r\n]/g, '');
  }
  return null;
}

describe('wsfed metadata', function () {
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
        uri: 'http://localhost:5050/wsfed/FederationMetadata/2007-06/FederationMetadata.xml'
      }, function (err, response, b){
        if(err) return done(err);
        content = b;
        doc = new xmldom.DOMParser().parseFromString(b).documentElement;
        done();
      });
    });

    it('sholud have the endpoint url', function(){
      expect(doc.getElementsByTagName('EndpointReference')[0].firstChild.textContent)
        .to.equal('http://localhost:5050/wsfed');
    });

    it('sholud have the claim types', function(){
      expect(doc.getElementsByTagName('auth:ClaimType'))
        .to.not.be.empty;
    });

    it('sholud have the issuer', function(){
      expect(doc.getAttribute('entityID'))
        .to.equal('fixture-test');
    });

    it('sholud have the pem', function(){
      expect(doc.getElementsByTagName('X509Certificate')[0].textContent)
        .to.equal(certToPem(server.credentials.cert));
    });

    it('should not contain line breaks', function(){
      expect(content)
        .to.not.contain('\n');
    });

  });
});