'use strict';

const expect = require('chai').expect;
const samlp = require('../lib');
const fs = require('fs');
const path = require('path');
const cheerio = require('cheerio');
const xmlhelper = require('./xmlhelper');
const zlib = require('zlib');
const url = require('url');

describe('samlp logout error', function() {
  const baseOptions = {
    issuer: 'issuer',
    id: 'id_123',
    protocolBinding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    destination: 'http://www.some-url.com/',
    key: fs.readFileSync(path.join(__dirname, 'fixture/samlp.test-cert.key')),
    cert: fs.readFileSync(path.join(__dirname, 'fixture/samlp.test-cert.pem'))
  };

  const mockRes = {
    set: (contentTypeHeader, contentType) => {
      expect(contentTypeHeader).to.equal('Content-Type');
      expect(contentType).to.equal('text/html');
    },
    redirect: () => {},
    send: () => {},
  };

  const req = {
    query: {
      RelayState: '123'
    }
  };

  const next = (err) => {
    expect(err).to.be.undefined;
  }

  it('with no error should return RESPONDER error', function(){
    const options = Object.assign({}, baseOptions, {
    });

    const res = Object.assign({}, mockRes, {
      send: (html) => {
        expect(html).to.be.ok;
        const $ = cheerio.load(html);
        const SAMLResponse = $('input[name="SAMLResponse"]').attr('value');
        const RelayState = $('input[name="RelayState"]').attr('value');        
        const decoded = new Buffer(SAMLResponse, 'base64').toString();
        expect(decoded).to.be.ok;
        expect(xmlhelper.getDestination(decoded)).to.equal(options.destination);
        expect(xmlhelper.getStatusCode(decoded)).to.equal('urn:oasis:names:tc:SAML:2.0:status:Responder');
        expect(RelayState).to.equal(req.query.RelayState);
      }
    });

    samlp.sendLogoutError(options)(req, res, next);
  });
  
  it('should send specified error', function(){
    const options = Object.assign({}, baseOptions, {
      error: {
        code: 'urn:oasis:names:tc:SAML:2.0:status:Requester'
      }
    });

    const res = Object.assign({}, mockRes, {
      send: (html) => {
        expect(html).to.be.ok;
        const $ = cheerio.load(html);
        const SAMLResponse = $('input[name="SAMLResponse"]').attr('value');
        const RelayState = $('input[name="RelayState"]').attr('value');        
        const decoded = new Buffer(SAMLResponse, 'base64').toString();
        expect(decoded).to.be.ok;
        expect(xmlhelper.getDestination(decoded)).to.equal(options.destination);
        expect(xmlhelper.getStatusCode(decoded)).to.equal(options.error.code);
        expect(RelayState).to.equal(req.query.RelayState);
      }
    });

    samlp.sendLogoutError(options)(req, res, next);    
  });

  it('should include description in response', function(){
    const options = Object.assign({}, baseOptions, {
      error: {
        code: 'urn:oasis:names:tc:SAML:2.0:status:Requester',
        description: 'An error has ocurred'
      }
    });

    const res = Object.assign({}, mockRes, {
      send: (html) => {
        expect(html).to.be.ok;
        const $ = cheerio.load(html);
        const SAMLResponse = $('input[name="SAMLResponse"]').attr('value');
        const RelayState = $('input[name="RelayState"]').attr('value');        
        const decoded = new Buffer(SAMLResponse, 'base64').toString();
        expect(decoded).to.be.ok;
        expect(xmlhelper.getDestination(decoded)).to.equal(options.destination);
        expect(xmlhelper.getStatusCode(decoded)).to.equal(options.error.code);
        expect(xmlhelper.getStatusMessage(decoded)).to.equal(options.error.description);
        expect(RelayState).to.equal(req.query.RelayState);
      }
    });

    samlp.sendLogoutError(options)(req, res, next);    
  });

  it('should return redirect if HTTP-Redirect binding is defined', function(done){
    const options = Object.assign({}, baseOptions, {
      protocolBinding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',      
      deflate: true
    });

    const res = Object.assign({}, mockRes, {
      redirect: (redirect_uri) => {
        const q = url.parse(redirect_uri, true).query;
        zlib.inflateRaw(new Buffer(q.SAMLResponse, 'base64'), function (err, decodedAndInflated) {
          if(err) return done(err);
          
          var decoded = decodedAndInflated.toString();
          expect(decoded).to.be.ok;
          expect(xmlhelper.getDestination(decoded)).to.equal(options.destination);
          done();
        });
      }
    });

    samlp.sendLogoutError(options)(req, res, next);    
  });

  it('should use options relay state if defined', function(){
    const options = Object.assign({}, baseOptions, {
      relayState : '456'
    });

    const res = Object.assign({}, mockRes, {
      send: (html) => {
        expect(html).to.be.ok;
        const $ = cheerio.load(html);
        const SAMLResponse = $('input[name="SAMLResponse"]').attr('value');
        const RelayState = $('input[name="RelayState"]').attr('value');        
        const decoded = new Buffer(SAMLResponse, 'base64').toString();
        expect(decoded).to.be.ok;
        expect(xmlhelper.getDestination(decoded)).to.equal(options.destination);
        expect(RelayState).to.equal(options.relayState);
      }
    });

    samlp.sendLogoutError(options)(req, res, next);    
  });

  it('should call next with error if options.destination is not defined', function(){
    const options = Object.assign({}, baseOptions);
    delete options.destination;

    samlp.sendLogoutError(options)(req, null, (err) => {
      expect(err).to.be.ok;
      expect(err.message).to.equal('Destination not specified');
    });    
  });
});
