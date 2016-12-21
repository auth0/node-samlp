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

  describe('HTTP Redirect', function(){
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
      });
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

        var params =  {
          query: {
            SAMLRequest: SAMLRequest,
            RelayState: sessionParticipantLogoutRequestRelayState,
            SigAlg: sessionParticipantLogoutRequestSigAlg,
            Signature: sessionParticipantLogoutRequestSignature
          }
        }; 

        expect(utils.validateSignature(params, "SAMLRequest", sessionParticipantLogoutRequest, { signingCert: server.credentials.cert.toString(), deflate: true })).to.be.undefined;
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

          var params =  {
            query: {
              SAMLResponse: SAMLResponse,
              RelayState: sessionParticipantLogoutResponseRelayState,
              SigAlg: sessionParticipantLogoutResponseSigAlg,
              Signature: sessionParticipantLogoutResponseSignature
            }
          };

          expect(utils.validateSignature(params, "SAMLResponse", sessionParticipantLogoutResponse, { signingCert: server.credentials.cert.toString(), deflate: true })).to.be.undefined;        
        });

        it('should remove session from sessions array', function () {
          expect(sessions.length).to.equal(0);
        });
      });
    });
  });

  describe('HTTP POST', function(){
    describe('SP initiated - 1 Session Participant', function () {
      var logoutResultValue, relayState, samlResponse;

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
        request.post({
          jar: request.jar(),
          followRedirect: false,
          uri: 'http://localhost:5050/logout',
          json: true,
          body: {
            SAMLRequest: 'PHNhbWxwOkxvZ291dFJlcXVlc3QgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgSUQ9InNhbWxyLTIyMGM3MDVlLWMxNWUtMTFlNi05OGE0LWVjZjRiYmNlNDMxOCIgSXNzdWVJbnN0YW50PSIyMDE2LTEyLTEzVDE4OjAxOjEyWiIgVmVyc2lvbj0iMi4wIj4KICA8c2FtbDpJc3N1ZXI+aHR0cHM6Ly9mb29iYXJzdXBwb3J0LnplbmRlc2suY29tPC9zYW1sOklzc3Vlcj48ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj48ZHM6U2lnbmVkSW5mbz48ZHM6Q2Fub25pY2FsaXphdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGRzaWctbW9yZSNyc2Etc2hhMjU2Ii8+PGRzOlJlZmVyZW5jZSBVUkk9IiNzYW1sci0yMjBjNzA1ZS1jMTVlLTExZTYtOThhNC1lY2Y0YmJjZTQzMTgiPjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiIvPjxkczpEaWdlc3RWYWx1ZT5tV1RvQUJuVExDd0xJOEFFOW1RYnFTZ3NCVnNsOXNpWG9sMG9yVXVUa0dBPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT5CSFdCdTdVbkJsNUF5VHFONFBnZEJ5M3lQc3IvZ0VPNG1KT0xPNm01Rm1tM1FtaVlOR0FlSWdJOVVXbmpuTnErWDc4QWE0SWIxbFBxOEsrblM5cTZ6UjEwK0xWZmM4U2YwR3dhdTdXTVpFNmVhR29PbCtCYUEvOGxUR0pBbGpScjJyNGtjME90S2w4dnJub2M0a3RGdXNsVUVOaDBaUXRYSkJiaTgvaEFzM1dXQTVNYldvQXJuUHJHTjFwK2pvdGIzOHc5ZnhEbUVhdG5yUmdXZ3BQa21GWVJockY5dkpEREJMeTkzbS9XQXc1c3NKbVFoYVNoaldtRkx2OVBpQ0ZRd08yV1B5Zk1RV2U5K2U0VDdXb3d1Y1ZkT2FZWHk5dm54REdXS01wSDBGVnRjR2ZRV0pmUzEwcXlCSHNwY25TemNVbUMxaWFPM3g1RzM0bUJXOXRzK1E9PTwvZHM6U2lnbmF0dXJlVmFsdWU+PGRzOktleUluZm8+PGRzOlg1MDlEYXRhLz48L2RzOktleUluZm8+PC9kczpTaWduYXR1cmU+CiAgPHNhbWw6TmFtZUlEIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6ZW1haWxBZGRyZXNzIj5mb29AZXhhbXBsZS5jb208L3NhbWw6TmFtZUlEPgogIDxzYW1sOlNlc3Npb25JbmRleD4xPC9zYW1sOlNlc3Npb25JbmRleD4KPC9zYW1scDpMb2dvdXRSZXF1ZXN0Pg==',
            RelayState: '123'
          }
        }, function (err, response){
          if(err) return done(err);
          expect(response.statusCode).to.equal(200);
          $ = cheerio.load(response.body);
          var SAMLResponse = $('input[name="SAMLResponse"]').attr('value');
          relayState = $('input[name="RelayState"]').attr('value');        
          samlResponse = new Buffer(SAMLResponse, 'base64');
          signedAssertion = /(<samlp:StatusCode.*\/>)/.exec(samlResponse)[1];
          var doc = new xmldom.DOMParser().parseFromString(signedAssertion);
          logoutResultValue = doc.documentElement.getAttribute('Value');
          done();
        });
      });

      it('should respond with a Success value', function () {
        expect(logoutResultValue).to.equal('urn:oasis:names:tc:SAML:2.0:status:Success');
      });

      it('should include RelayState', function () {
        expect(relayState).to.equal('123');
      });

      it('should remove session from sessions array', function () {
        expect(sessions.length).to.equal(0);
      });
    });

    describe('SP initiated - 2 Session Participants', function () {
      var SAMLRequest;
      var sessionParticipantLogoutRequest;
      var sessionParticipantLogoutRequestRelayState;

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

      // <samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="samlr-220c705e-c15e-11e6-98a4-ecf4bbce4318" IssueInstant="2016-12-13T18:01:12Z" Version="2.0">
      //   <saml:Issuer>https://foobarsupport.zendesk.com</saml:Issuer>
      //   <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">foo@example.com</saml:NameID>
      //   <saml:SessionIndex>1</saml:SessionIndex>
      // </samlp:LogoutRequest>
      before(function (done) {
        request.post({
          jar: request.jar(),
          followRedirect: false,
          uri: 'http://localhost:5050/logout',
          json: true,
          body: {
            SAMLRequest: 'PHNhbWxwOkxvZ291dFJlcXVlc3QgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgSUQ9InNhbWxyLTIyMGM3MDVlLWMxNWUtMTFlNi05OGE0LWVjZjRiYmNlNDMxOCIgSXNzdWVJbnN0YW50PSIyMDE2LTEyLTEzVDE4OjAxOjEyWiIgVmVyc2lvbj0iMi4wIj4KICA8c2FtbDpJc3N1ZXI+aHR0cHM6Ly9mb29iYXJzdXBwb3J0LnplbmRlc2suY29tPC9zYW1sOklzc3Vlcj48ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj48ZHM6U2lnbmVkSW5mbz48ZHM6Q2Fub25pY2FsaXphdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGRzaWctbW9yZSNyc2Etc2hhMjU2Ii8+PGRzOlJlZmVyZW5jZSBVUkk9IiNzYW1sci0yMjBjNzA1ZS1jMTVlLTExZTYtOThhNC1lY2Y0YmJjZTQzMTgiPjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiIvPjxkczpEaWdlc3RWYWx1ZT5tV1RvQUJuVExDd0xJOEFFOW1RYnFTZ3NCVnNsOXNpWG9sMG9yVXVUa0dBPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT5CSFdCdTdVbkJsNUF5VHFONFBnZEJ5M3lQc3IvZ0VPNG1KT0xPNm01Rm1tM1FtaVlOR0FlSWdJOVVXbmpuTnErWDc4QWE0SWIxbFBxOEsrblM5cTZ6UjEwK0xWZmM4U2YwR3dhdTdXTVpFNmVhR29PbCtCYUEvOGxUR0pBbGpScjJyNGtjME90S2w4dnJub2M0a3RGdXNsVUVOaDBaUXRYSkJiaTgvaEFzM1dXQTVNYldvQXJuUHJHTjFwK2pvdGIzOHc5ZnhEbUVhdG5yUmdXZ3BQa21GWVJockY5dkpEREJMeTkzbS9XQXc1c3NKbVFoYVNoaldtRkx2OVBpQ0ZRd08yV1B5Zk1RV2U5K2U0VDdXb3d1Y1ZkT2FZWHk5dm54REdXS01wSDBGVnRjR2ZRV0pmUzEwcXlCSHNwY25TemNVbUMxaWFPM3g1RzM0bUJXOXRzK1E9PTwvZHM6U2lnbmF0dXJlVmFsdWU+PGRzOktleUluZm8+PGRzOlg1MDlEYXRhLz48L2RzOktleUluZm8+PC9kczpTaWduYXR1cmU+CiAgPHNhbWw6TmFtZUlEIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6ZW1haWxBZGRyZXNzIj5mb29AZXhhbXBsZS5jb208L3NhbWw6TmFtZUlEPgogIDxzYW1sOlNlc3Npb25JbmRleD4xPC9zYW1sOlNlc3Npb25JbmRleD4KPC9zYW1scDpMb2dvdXRSZXF1ZXN0Pg==',
            RelayState: '123'
          }
        }, function (err, response){
          if(err) return done(err);
          expect(response.statusCode).to.equal(200);
          $ = cheerio.load(response.body);
          // 
          SAMLRequest = $('input[name="SAMLRequest"]').attr('value');
          sessionParticipantLogoutRequestRelayState = $('input[name="RelayState"]').attr('value');
          sessionParticipantLogoutRequest = new Buffer(SAMLRequest, 'base64').toString();
          done();
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

        // TODO: Review as we need to merge validation methods
        var doc = new xmldom.DOMParser().parseFromString(sessionParticipantLogoutRequest);        
        expect(utils.validateSignature({body : { SAMLRequest: SAMLRequest }}, "SAMLRequest", doc, { signingCert: sessionParticipant1.cert })).to.be.undefined;
      });

      describe('should send Session Participant LogoutResponse to the SAML IdP', function () {
        var SAMLResponse;
        var sessionParticipantLogoutResponse;
        var sessionParticipantLogoutResponseRelayState;

        before(function (done) {
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
          request.post({
            jar: request.jar(),
            followRedirect: false,
            uri: 'http://localhost:5050/logout',
            json: true,
            body: {
              SAMLResponse: 'PHNhbWxwOkxvZ291dFJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIElEPSJfMmJiYTZlYTVlNjc3ZDgwN2YwNmEiIEluUmVzcG9uc2VUbz0ic2FtbHItMjIwYzcwNWUtYzE1ZS0xMWU2LTk4YTQtZWNmNGJiY2U0MzE4IiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAxNi0xMi0xNlQxMzozNzo1N1oiIERlc3RpbmF0aW9uPSJodHRwOi8vbG9jYWxob3N0OjUwNTAvbG9nb3V0Ij4KICAgIDxzYW1sOklzc3VlciB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj5odHRwczovL2Zvb2JhcnN1cHBvcnQuZXhhbXBsZS5jb208L3NhbWw6SXNzdWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI3JzYS1zaGEyNTYiLz48ZHM6UmVmZXJlbmNlIFVSST0iI18yYmJhNmVhNWU2NzdkODA3ZjA2YSI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHM6VHJhbnNmb3Jtcz48ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjc2hhMjU2Ii8+PGRzOkRpZ2VzdFZhbHVlPkxXUmUrbGNNR0VRYTlPYjlsc0hpUk5Ob29pUDgyM2JwVFA2OFVXMUdRR0U9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2RzOlNpZ25lZEluZm8+PGRzOlNpZ25hdHVyZVZhbHVlPlAxeUdBaGxJZEQvZUFYWERUb0JSQ3VXekxneldxaEZpQURqMDRLcmMvSmNaNlZwVjJhVXpSWjJDR21SOUZaNVdXZlU2VVB0SG5VYU1iSVR6NjZFSEdBaCtNcC9JajNJWU1qeVltWnJtTDhJSlFZWHkzMTFwU2REQnU4REJJUm5aQkpLSG5EV0VtT0doS2NJcHhTa1hveVd3NlpCK090VWh5d3dGKzVPMXh5cnk0alJQODlxV28wN2M0MzZaMHNkbWNhZkRkU1NpeTdkMVRVMUphN0VUYnhBYnVaSFRwUDNYSzFLeTdrNUZWU3ZxcCtYc2xsVTBTWTlkMWhFd0ZlSEpnOWdCa2xxVm1iYUdGV0FhK0xZTGoxWGd2KzBnejdWa2ptVTJUV2ZZQVE2MU9vbkJ5TWpKcWFqbk5oWkorODN6L2RLbWZSd200V3FUK0hwVFVJcUhaQT09PC9kczpTaWduYXR1cmVWYWx1ZT48ZHM6S2V5SW5mbz48ZHM6WDUwOURhdGEvPjwvZHM6S2V5SW5mbz48L2RzOlNpZ25hdHVyZT4KICAgIDxzYW1scDpTdGF0dXM+PHNhbWxwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIvPgogICAgPC9zYW1scDpTdGF0dXM+Cjwvc2FtbHA6TG9nb3V0UmVzcG9uc2U+',
              RelayState: '123'
            }
          }, function (err, response) {
            if (err) { return done(err); }
            $ = cheerio.load(response.body);
            SAMLResponse = $('input[name="SAMLResponse"]').attr('value');
            sessionParticipantLogoutResponseRelayState = $('input[name="RelayState"]').attr('value');        
            sessionParticipantLogoutResponse = new Buffer(SAMLResponse, 'base64').toString();
            done();
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
          var signedAssertion = /(<samlp:StatusCode.*\/>)/.exec(new Buffer(SAMLResponse, 'base64'))[1];
          var doc = new xmldom.DOMParser().parseFromString(signedAssertion);
          var logoutResultValue = doc.documentElement.getAttribute('Value');
          expect(logoutResultValue).to.equal('urn:oasis:names:tc:SAML:2.0:status:Success');
        });

        it('should validate LogoutResponse signature', function () {
          expect(SAMLResponse).to.exist;
          expect(sessionParticipantLogoutResponseRelayState).to.exist;
          
          // TODO: Review as we need to merge validation methods          
          var doc = new xmldom.DOMParser().parseFromString(sessionParticipantLogoutResponse);                  
          expect(utils.validateSignature({body : { SAMLResponse: SAMLResponse }}, "SAMLResponse", doc, { signingCert: sessionParticipant2.cert })).to.be.undefined;
        });

        it('should remove session from sessions array', function () {
          expect(sessions.length).to.equal(0);
        });
      });
    });
  });
});