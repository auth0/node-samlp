var expect = require('chai').expect;
var server = require('./fixture/server');
var request = require('request');
var cheerio = require('cheerio');
var xmlhelper = require('./xmlhelper');
var xmldom = require('@auth0/xmldom');

describe('samlp signed response', function () {
  before(function (done) {
    server.start({
      audience: 'https://auth0-dev-ed.my.salesforce.com',
      destination: 'http://destination',
      signResponse: true }, done);
  });

  after(function (done) {
    server.close(done);
  });

  describe('SAMLRequest on querystring', function () {
    var body, $, signedResponse, attributes;

    before(function (done) {
      request.get({
        jar: request.jar(),
        uri: 'http://localhost:5050/samlp?SAMLRequest=fZJbc6owFIX%2FCpN3EAEVMmIHEfDaqlCP%2BtKJELkUEkqCl%2F76Uj3O9JyHPmay9l4r%2BVb%2F6VLkwglXLKXEBG1JBgImIY1SEpvgNXBFHTwN%2BgwVeQmtmidkjT9qzLjQzBEGbxcmqCsCKWIpgwQVmEEeQt9azKEiybCsKKchzYFgMYYr3hjZlLC6wJWPq1Ma4tf13AQJ5yWDrVZO45RIDOWYHWkVYimkBRBGjWVKEL%2BlfEhDSjhlVEJNLvlb1%2FqOA4TJyARvynPH80qFFJPAdg%2Fh1fNnGVqpKO3OLkZonUfJ0Nu2Y2t6PdlVPj1RZxVlThywI8rihVH0MuksTQz3sx1Fm2xv5LO9nYSs5KXxfnm364%2FwfMDPWMqn182qHOqpjzR0dncsM6xO1Vs7h860HI97yrB7xHE9dt2loy%2FQu1prie%2FMcuNNL2i6nUdWp%2Fdnk3yekb7dXYhWjFjil%2Br2IC%2Bd%2FexlNF7wS77Zomvo7epFbCuyVx5tq3klYzWeEMYR4SZQ5LYqypqo6IGiQE2FmiKpencPhOXf%2Fx%2Bm5E71N1iHu4jBcRAsxeWLHwBh82hHIwD3LsCbefWjBL%2BvRQ%2FyYPCAd4MmRvgk4kgqrv8R77d%2B2Azup38LOPgC&RelayState=123'
      }, function (err, response, b){
        if(err) return done(err);
        body = b;
        $ = cheerio.load(body);
        var SAMLResponse = $('input[name="SAMLResponse"]').attr('value');
        var decoded = new Buffer(SAMLResponse, 'base64').toString();
        signedResponse = /(<samlp:Response.*<\/samlp:Response>)/.exec(decoded)[1];
        done();
      });
    });

    it('should contain a valid signed response', function(){
      var isValid = xmlhelper.verifySignature(
                signedResponse,
                server.credentials.cert);
      expect(isValid).to.be.ok;
    });

    it('should use sha256 as default signature algorithm', function(){
      var algorithm = xmlhelper.getSignatureMethodAlgorithm(signedResponse);
      expect(algorithm).to.equal('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
    });

    it('should use sha256 as default diigest algorithm', function(){
      var algorithm = xmlhelper.getDigestMethodAlgorithm(signedResponse);
      expect(algorithm).to.equal('http://www.w3.org/2001/04/xmlenc#sha256');
    });

    it('should use destination if defined', function(){
      var destination = xmlhelper.getDestination(signedResponse);
      expect(destination).to.equal('http://destination');
    });

    it('should have signature after issuer', function(){
      var doc = new xmldom.DOMParser().parseFromString(signedResponse);
      var signature = doc.documentElement.getElementsByTagName('Signature');
      expect(signature[0].previousSibling.nodeName).to.equal('saml:Issuer');
    });
  });
});