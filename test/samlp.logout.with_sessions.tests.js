var expect        = require('chai').expect;
var server        = require('./fixture/server');
var request       = require('request');
var cheerio       = require('cheerio');
var xmldom        = require('xmldom');
var xmlhelper     = require('./xmlhelper');
var zlib          = require('zlib');
var utils         = require('../lib/utils');
var qs            = require('querystring');
var InMemoryStore = require('../lib/in_memory_store');

describe('samlp logout with Session Participants', function () {
  var sessions = [];
  var samlIdPIssuer = 'urn:fixture-test';
  var testStore = new InMemoryStore();

  before(function (done) {
    server.start( { 
      audience: 'https://auth0-dev-ed.my.salesforce.com',
      issuer: samlIdPIssuer,
      store: testStore,
      getSessions: function (cb) {
        cb(null, sessions);
      }
    },done);
  });

  after(function (done) {
    server.close(done);
  });

  var body, $, signedAssertion;

  beforeEach(function (done) {
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
      done();
    });
  });

  describe('SP initiated - 1 Session Participant', function () {
    var logoutResultValue;

    before(function () {
      testStore.clear();

      sessions.push({
        serviceProviderId : 'https://foobarsupport.zendesk.com',
        nameID: 'foo@example.com',
        sessionIndex: '1',
        serviceProviderLogoutURL: 'https://example.com/logout',
      });
    });

    // SAMLRequest: base64 encoded + deflated + URLEncoded
    // Signature: URLEncoded
    // SigAlg: URLEncoded

    // <samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="samlr-220c705e-c15e-11e6-98a4-ecf4bbce4318" IssueInstant="2016-12-13T18:01:12Z" Version="2.0">
    //   <saml:Issuer>https://foobarsupport.zendesk.com</saml:Issuer>
    //   <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">foo@example.com</saml:NameID>
    //   <saml:SessionIndex>1</saml:SessionIndex>
    // </samlp:LogoutRequest>
    before(function (done) {
      request.get({
        jar: request.jar(),
        followRedirect: false,
        uri: 'http://localhost:5050/logout?SAMLRequest=fZFBS8NAEIXvhf6HsPdNM2mtdWiDhSIEqgdbPHjbbqYazO7GnQ0Uf73bVDAKetnDm%2B%2FNm8cuWZmmxa17cV14pPeOOCQn01jGfrISnbfoFNeMVhliDBp36%2Fst5mmGrXfBadeIgeV%2Fh2ImH2pnRVJuVuJs8DLPM32dXZHUEB8AmsubhZpJ0sfZ4aBpNoVF5Jk7Ki0HZcNK5BnMJeQSpntYYAYI%2BbNInshzXB7HaSaK8ShJlucI7L2%2BeA2hZZxMjs4dlOeubZ0P6QfZivgt1c4sJ0P82%2F8Qi5Sb5M55o8LfDSGFXqkreexRJKPqZl1VnphFEXNv6aRM29Ag7bJ8kLaLcGxRxrNOBXxRP8Tx6KL%2B%2BrniEw%3D%3D&Signature=KH%2FBMO0DJyS2Ffy%2B6Rnb11pAF37Y%2Beua7RHcFhVrwgxJEqsx59vTelrfPt771JPfr7%2BoG1uYwwO3Algs59yTeqmU35x18Bf2e0yWugqEF7wxHETCjrwbCK1YjYg0ilwCojk%2FBTTv2Rs%2BY7RB21Ou1GShT1uXv8WItj7E2qnr%2B6kHY5XJWTJukZa9Vnkx%2FiisA7n6UfnnGcWMdltYeOvyHvOFMVG43dDxBms9WKMKdxn6NJ7i2V1v7nXj1DoXD4PDH5B6aevkA49c6mpzozyXKLeXLys%2FvPNNT4cC1jmWvuen5pe%2FE1WfgcZcZvj2GGaxs36fdH%2FHsIcyDvE%2Bj7ngYw%3D%3D&RelayState=123&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1'
      }, function (err, response){
        if(err) return done(err);
        expect(response.statusCode).to.equal(302);
        var qs = require('querystring');
        var i = response.headers.location.indexOf('SAMLResponse=');
        var SAMLResponse = qs.parse(response.headers.location.substr(i)).SAMLResponse;
        
        zlib.inflateRaw(new Buffer(SAMLResponse, 'base64'), function (err, decodedAndInflated) {
          if(err) return done(err);
          signedAssertion = /(<samlp:StatusCode.*\/>)/.exec(decodedAndInflated)[1];
          var doc = new xmldom.DOMParser().parseFromString(signedAssertion);
          logoutResultValue = doc.documentElement.getAttribute('Value');

          done();
        });
      });
    });

    it('should respond with a Success value', function () {
      expect(logoutResultValue).to.equal('urn:oasis:names:tc:SAML:2.0:status:Success');
    });

    it('should remove session from sessions array', function () {
      expect(sessions.length).to.equal(0);
    })
  });

  describe('SP initiated - 2 Session Participants', function () {
    var SAMLRequest;
    var sessionParticipantLogoutRequest;
    var sessionParticipantLogoutRequestRelayState;
    var sessionParticipantLogoutRequestSigAlg;
    var sessionParticipantLogoutRequestSignature;

    var sessionParticipant1 = { // Logout Initiator
      serviceProviderId : 'https://foobarsupport.zendesk.com', // Issuer
      nameID: 'foo@example.com',
      sessionIndex: '1',
      serviceProviderLogoutURL: 'https://foobarsupport.zendesk.com/logout',
      cert: server.credentials.cert // SP1 public Cert
    };

    var sessionParticipant2 = {
      serviceProviderId : 'https://foobarsupport.example.com', // Issuer
      nameID: 'bar@example.com',
      sessionIndex: '2',
      serviceProviderLogoutURL: 'https://foobarsupport.example.com/logout',
      cert: server.credentials.cert // SP2 public Cert
    };

    before(function () {
      testStore.clear();

      sessions.push(sessionParticipant1);
      sessions.push(sessionParticipant2);
    });

    // SAMLRequest: base64 encoded + deflated + URLEncoded
    // Signature: URLEncoded
    // SigAlg: URLEncoded

    // <samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="samlr-220c705e-c15e-11e6-98a4-ecf4bbce4318" IssueInstant="2016-12-13T18:01:12Z" Version="2.0">
    //   <saml:Issuer>https://foobarsupport.zendesk.com</saml:Issuer>
    //   <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">foo@example.com</saml:NameID>
    //   <saml:SessionIndex>1</saml:SessionIndex>
    // </samlp:LogoutRequest>
    before(function (done) {
      request.get({
        jar: request.jar(),
        followRedirect: false,
        uri: 'http://localhost:5050/logout?SAMLRequest=fZFBS8NAEIXvhf6HsPdNM2mtdWiDhSIEqgdbPHjbbqYazO7GnQ0Uf73bVDAKetnDm%2B%2FNm8cuWZmmxa17cV14pPeOOCQn01jGfrISnbfoFNeMVhliDBp36%2Fst5mmGrXfBadeIgeV%2Fh2ImH2pnRVJuVuJs8DLPM32dXZHUEB8AmsubhZpJ0sfZ4aBpNoVF5Jk7Ki0HZcNK5BnMJeQSpntYYAYI%2BbNInshzXB7HaSaK8ShJlucI7L2%2BeA2hZZxMjs4dlOeubZ0P6QfZivgt1c4sJ0P82%2F8Qi5Sb5M55o8LfDSGFXqkreexRJKPqZl1VnphFEXNv6aRM29Ag7bJ8kLaLcGxRxrNOBXxRP8Tx6KL%2B%2BrniEw%3D%3D&Signature=KH%2FBMO0DJyS2Ffy%2B6Rnb11pAF37Y%2Beua7RHcFhVrwgxJEqsx59vTelrfPt771JPfr7%2BoG1uYwwO3Algs59yTeqmU35x18Bf2e0yWugqEF7wxHETCjrwbCK1YjYg0ilwCojk%2FBTTv2Rs%2BY7RB21Ou1GShT1uXv8WItj7E2qnr%2B6kHY5XJWTJukZa9Vnkx%2FiisA7n6UfnnGcWMdltYeOvyHvOFMVG43dDxBms9WKMKdxn6NJ7i2V1v7nXj1DoXD4PDH5B6aevkA49c6mpzozyXKLeXLys%2FvPNNT4cC1jmWvuen5pe%2FE1WfgcZcZvj2GGaxs36fdH%2FHsIcyDvE%2Bj7ngYw%3D%3D&RelayState=123&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1'
      }, function (err, response){
        if(err) return done(err);
        // First it should come the LogoutRequest to the 2nd Session Participant as a redirect
        expect(response.statusCode).to.equal(302);

        var i = response.headers.location.indexOf('?');
        var completeQueryString = response.headers.location.substr(i+1);
        var parsedQueryString = qs.parse(completeQueryString);

        SAMLRequest = parsedQueryString.SAMLRequest;
        sessionParticipantLogoutRequestRelayState = parsedQueryString.RelayState;
        sessionParticipantLogoutRequestSigAlg = parsedQueryString.SigAlg;
        sessionParticipantLogoutRequestSignature = parsedQueryString.Signature;

        zlib.inflateRaw(new Buffer(SAMLRequest, 'base64'), function (err, decodedAndInflated) {
          if(err) return done(err);
          sessionParticipantLogoutRequest = decodedAndInflated.toString();

          done();
        });
      });
    });

    it('should validate LogoutRequest to Session Participant', function () {
      expect(sessionParticipantLogoutRequest).to.exist;
      expect(xmlhelper.getIssueInstant(sessionParticipantLogoutRequest)).to.exist;
      expect(xmlhelper.getDestination(sessionParticipantLogoutRequest)).to.equal(sessionParticipant2.serviceProviderLogoutURL);
      expect(xmlhelper.getConsent(sessionParticipantLogoutRequest)).to.equal('urn:oasis:names:tc:SAML:2.0:consent:unspecified');
      expect(xmlhelper.getElementText(sessionParticipantLogoutRequest, 'Issuer')).to.equal(samlIdPIssuer);
      expect(xmlhelper.getElementText(sessionParticipantLogoutRequest, 'NameID')).to.equal(sessionParticipant2.nameID);
      expect(xmlhelper.getElementText(sessionParticipantLogoutRequest, 'samlp:SessionIndex')).to.equal(sessionParticipant2.sessionIndex);
    });

    it('should validate LogoutRequest signature', function () {
      expect(SAMLRequest).to.exist;
      expect(sessionParticipantLogoutRequestRelayState).to.exist;
      expect(sessionParticipantLogoutRequestSigAlg).to.exist;
      expect(sessionParticipantLogoutRequestSignature).to.exist;

      var signedParams =  {
        SAMLRequest: SAMLRequest,
        RelayState: sessionParticipantLogoutRequestRelayState,
        SigAlg: sessionParticipantLogoutRequestSigAlg
      }; 

      var alg = sessionParticipantLogoutRequestSigAlg.split('#')[1].toUpperCase();

      expect(utils.validateSignature(sessionParticipantLogoutRequestSignature,
        qs.stringify(signedParams), server.credentials.cert.toString(), alg)).to.be.true;
    });

    describe('should send Session Participant LogoutResponse to the SAML IdP', function () {
      var SAMLResponse;
      var sessionParticipantLogoutResponse;
      var sessionParticipantLogoutResponseRelayState;
      var sessionParticipantLogoutResponseSigAlg;
      var sessionParticipantLogoutResponseSignature;

      before(function (done) {
        // SAMLResponse: base64 encoded + deflated + URLEncoded
        // Signature: URLEncoded
        // SigAlg: URLEncoded
        // 
        // <samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        //   ID="_2bba6ea5e677d807f06a"
        //   InResponseTo="samlr-220c705e-c15e-11e6-98a4-ecf4bbce4318"
        //   Version="2.0"
        //   IssueInstant="2016-12-16T13:37:57Z"
        //   Destination="http://localhost:5050/logout">
        //     <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://foobarsupport.example.com</saml:Issuer>
        //     <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
        //     </samlp:Status>
        // </samlp:LogoutResponse>
        request.get({
          jar: request.jar(),
          followRedirect: false,
          uri: 'http://localhost:5050/logout?SAMLResponse=fZHBisJADIbvgu9Q5l47U23rBltY1ovgXlbx4GWZjnEV2skwmYKPv21F0IuXgSR%2F%2Fi%2FJrFi3jYMt%2FVEXfpAdWcbo1jaWYSyVovMWSPOVweoWGYKB3ef3FtKZBOcpkKFGTCdRtFmX4jeta52jzjAvitNSFmeZ63vVPuz3VIrB28dpKk0hM4yN6h%2BlMI8%2FlnoRozkv6trgYq6WY%2FMBPV%2FJlqKH3t2YO9xYDtqGPitVHqs0VvlezWFeQFYcR9kaOVytDmPvJQQHSdKQ0c2FOEAmM9mHw%2BqiGuRRtBoGg9HdP53h%2FRU0M%2FqBIaqBwT3kTFRrz51z5MMMb7p1Dc4MtavkifAMdbALOnRcvURfdMLooJsO34%2FAoxp2nTHILJKHc%2FJiPZ08Eq8fXv0D&Signature=TvghU9Ct8N5JXHaN3dG8oCeaBlJawQ9Tw9a6Qsx4qh%2FGh7fGfiLQBZOncyfXQdh7aKrjPUJ%2FENwlpB2mlUsOGD3z5Hq9tI2Z42nBXT8xnEXhTfF%2Frn259HWYZhxB4mSmOffhWUibkKYqvSomulwtQ%2FvX%2FY80GquccJXiwSyf4Y2QsKUfktuaoNX6vyD4W9CGWk0EWw1jWHPKxEDU8fXeNw4PUsNlP0%2BQZx6QcPqvXAtWQgawzw%2FwfeqBwjen%2BJjR4MPegB7rPS9D6XzZMzt9T5ApjUOiiCJ1agmSDGvQhqguP9UHzZDmO0M4p%2BwYnOtgQ0QRRaOlUIjhj48vFl%2FIXA%3D%3D&RelayState=123&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1'
        }, function (err, response) {
          if (err) { return done(err); }

          expect(response.statusCode).to.equal(302);
          var qs = require('querystring');

          var i = response.headers.location.indexOf('?');
          var completeQueryString = response.headers.location.substr(i+1);
          var parsedQueryString = qs.parse(completeQueryString);

          SAMLResponse = parsedQueryString.SAMLResponse;
          sessionParticipantLogoutResponseRelayState = parsedQueryString.RelayState;
          sessionParticipantLogoutResponseSigAlg = parsedQueryString.SigAlg;
          sessionParticipantLogoutResponseSignature = parsedQueryString.Signature;

          zlib.inflateRaw(new Buffer(SAMLResponse, 'base64'), function (err, decodedAndInflated) {
            if(err) return done(err);
            sessionParticipantLogoutResponse = decodedAndInflated.toString();

            done();
          });
        });
      });

      it('should validate LogoutResponse to the Session Participant that initiated the logout', function () {
        expect(sessionParticipantLogoutResponse).to.exist;
        expect(xmlhelper.getIssueInstant(sessionParticipantLogoutResponse)).to.exist;
        // expect(xmlhelper.getDestination(sessionParticipantLogoutResponse)).to.equal(sessionParticipant1.serviceProviderLogoutURL); //TODO
        //TODO InResponseTo
        expect(xmlhelper.getIssuer(sessionParticipantLogoutResponse)).to.equal(samlIdPIssuer);
      });

      it('should respond with a Success value', function () {
        var signedAssertion = /(<samlp:StatusCode.*\/>)/.exec(sessionParticipantLogoutResponse)[1];
        var doc = new xmldom.DOMParser().parseFromString(signedAssertion);
        var logoutResultValue = doc.documentElement.getAttribute('Value');
        expect(logoutResultValue).to.equal('urn:oasis:names:tc:SAML:2.0:status:Success');
      });

      it('should validate LogoutResponse signature', function () {
        expect(SAMLResponse).to.exist;
        expect(sessionParticipantLogoutResponseRelayState).to.exist;
        expect(sessionParticipantLogoutResponseSigAlg).to.exist;
        expect(sessionParticipantLogoutResponseSignature).to.exist;

        var signedParams =  {
          SAMLResponse: SAMLResponse,
          RelayState: sessionParticipantLogoutResponseRelayState,
          SigAlg: sessionParticipantLogoutResponseSigAlg
        }; 

        var alg = sessionParticipantLogoutResponseSigAlg.split('#')[1].toUpperCase();

        expect(utils.validateSignature(sessionParticipantLogoutResponseSignature,
          qs.stringify(signedParams), server.credentials.cert.toString(), alg)).to.be.true;
      });

      it('should remove session from sessions array', function () {
        expect(sessions.length).to.equal(0);
      })
    })
  });
});