var expect        = require('chai').expect;
var server        = require('./fixture/server');
var request       = require('request').defaults({ jar:true  });
var cheerio       = require('cheerio');
var xmldom        = require('@auth0/xmldom');
var xmlhelper     = require('./xmlhelper');
var zlib          = require('zlib');
var utils         = require('../lib/utils');
var qs            = require('querystring');
var signers       = require('../lib/signers');
var fs            = require('fs');
var path          = require('path');
var SPs           = require('../lib/sessionParticipants');
const timekeeper  = require('timekeeper');
const BINDINGS    = require('../lib/constants').BINDINGS;

var sp1_credentials = {
  cert:     fs.readFileSync(path.join(__dirname, 'fixture', 'sp1.pem')),
  key:      fs.readFileSync(path.join(__dirname, 'fixture', 'sp1.key')),
};

var sp2_credentials = {
  cert:     fs.readFileSync(path.join(__dirname, 'fixture', 'sp2.pem')),
  key:      fs.readFileSync(path.join(__dirname, 'fixture', 'sp2.key')),
};

var sessionParticipant1 = {
  serviceProviderId : 'https://foobarsupport.zendesk.com', // Issuer
  nameId: 'foo@example.com',
  nameIdFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
  sessionIndex: '1',
  serviceProviderLogoutURL: 'https://foobarsupport.zendesk.com/logout',
  cert: sp1_credentials.cert // SP1 public Cert
};

var sessionParticipant2 = {
  serviceProviderId : 'https://foobarsupport.example.com', // Issuer
  nameId: 'bar@example.com',
  nameIdFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
  sessionIndex: '2',
  serviceProviderLogoutURL: 'https://foobarsupport.example.com/logout',
  cert: sp2_credentials.cert // SP2 public Cert
};

describe('samlp logout with Session Participants - Session Provider', function () {
  var sessions = [], returnError;
  var samlIdPIssuer = 'urn:fixture-test';

  var frozenTime;
  before(() => {
    frozenTime = Date.now();
    timekeeper.freeze(frozenTime);
  });

  after(() => timekeeper.reset());

  before(function (done) {
    server.start( {
      audience: 'https://auth0-dev-ed.my.salesforce.com',
      issuer: samlIdPIssuer,
      clearIdPSession: function(cb){
        if (returnError){
          return cb(new Error('There was an error cleaning session'));
        }
        cb();
      },
      sessionParticipants: new SPs(sessions)
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

  function prepareOneParticipant(binding) {
    sessions.splice(0);
    sessions.push({ ...sessionParticipant1, binding: binding });
  }

  function prepareTwoParticipants(secondBinding) {
    sessions.splice(0);
    sessions.push(sessionParticipant1);
    sessions.push({ ...sessionParticipant2, binding: secondBinding });
  }

  function logoutGetSPInitiated(callback) {
    // SAMLRequest: base64 encoded + deflated + URLEncoded
    // Signature: URLEncoded
    // SigAlg: URLEncoded

    // <samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="samlr-220c705e-c15e-11e6-98a4-ecf4bbce4318" IssueInstant="2016-12-13T18:01:12Z" Version="2.0">
    //   <saml:Issuer>https://foobarsupport.zendesk.com</saml:Issuer>
    //   <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">foo@example.com</saml:NameID>
    //   <saml:SessionIndex>1</saml:SessionIndex>
    // </samlp:LogoutRequest>
    request.get(
      {
        followRedirect: false,
        uri: 'http://localhost:5050/logout?SAMLRequest=fVFNS8NAEL0L%2Foew900zaa1xaIOFIgSqBysevG03Uw1md%2BPOBoq%2F3m1aoVZ0DnOY97WPnbEybYcr9%2Br68EgfPXFIdqa1jAMyF7236BQ3jFYZYgwa14v7FeZphp13wWnXihPJ%2FwrFTD40zoqkWs7FXuBlnmf6OrsiqSEuAJrKm0JNJOntZLPRNBlDEfnMPVWWg7JhLvIMphJyCeMnKDADhPxFJM%2FkOZpHOM1EeXmRHGe2D8LBwZdvIXSMo9HWuY3y3Hed8yH9JFsTv6famdnolH7u8hBLVcvkznmjwt9tIYXh0tRyO1CRjGraRV17YhZlTL%2BlnTJdSyeZB%2FNfmesoib2q%2BMRdCUfuj%2BO34oCd%2FWj5BQ%3D%3D&Signature=NkobB0DS0M4kfV89R%2Bma0wp0djNr4GW2ziVemwSvVYy2iF432qjs%2FC4Y1cZDXwuF5OxMgu4DuelS5mW3Z%2B46XXkoMVBizbd%2BIuJUFQcvLtiXHkoaEk8HVU0v5bA9TDoc9Ve7A0nUgKPciH7KTcFSr45vepyg0dMMQtarsUZeYSRPM0QlwxXKCWRQJDwGHLie5dMCZTRNUEcm9PtWZij714j11HI15u6Fp5GDnhp7mzKuAUdSIKHzNKAS2J4S8xZz9n9UTCl3uBbgfxZ3av6%2FMQf7HThxTl%2FIOmU%2FYCAN6DWWE%2BQ3Z11bgU06P39ZuLW2fRBOfIOO6iTEaAdORrdBOw%3D%3D&RelayState=123&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1',
      },
      function (err, response) {
        if (err) return callback(err);
        callback(null, response);
      }
    );
  }

  function logoutPostSPInitiated(callback) {
    // SAMLRequest: base64 encoded + deflated + URLEncoded
    // Signature: URLEncoded
    // SigAlg: URLEncoded

    // <samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="samlr-220c705e-c15e-11e6-98a4-ecf4bbce4318" IssueInstant="2016-12-13T18:01:12Z" Version="2.0">
    //   <saml:Issuer>https://foobarsupport.zendesk.com</saml:Issuer>
    //   <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">foo@example.com</saml:NameID>
    //   <saml:SessionIndex>1</saml:SessionIndex>
    // </samlp:LogoutRequest>
    request.post({
        followRedirect: false,
        uri: "http://localhost:5050/logout",
        json: true,
        body: {
          SAMLRequest: "PD94bWwgdmVyc2lvbj0iMS4wIj8+DQo8c2FtbHA6TG9nb3V0UmVxdWVzdCB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0icGZ4NmZlNjU3ZTMtMWE3Zi04OTNlLWY2OTAtZjdmYzUxNjJlYTExIiBJc3N1ZUluc3RhbnQ9IjIwMTYtMTItMTNUMTg6MDE6MTJaIiBWZXJzaW9uPSIyLjAiPg0KICAgICAgICA8c2FtbDpJc3N1ZXI+aHR0cHM6Ly9mb29iYXJzdXBwb3J0LnplbmRlc2suY29tPC9zYW1sOklzc3Vlcj48ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj4NCiAgPGRzOlNpZ25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz4NCiAgICA8ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3JzYS1zaGExIi8+DQogIDxkczpSZWZlcmVuY2UgVVJJPSIjcGZ4NmZlNjU3ZTMtMWE3Zi04OTNlLWY2OTAtZjdmYzUxNjJlYTExIj48ZHM6VHJhbnNmb3Jtcz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PC9kczpUcmFuc2Zvcm1zPjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjc2hhMSIvPjxkczpEaWdlc3RWYWx1ZT55SnpIbmRqL3NuaVJzTG1kcHFSZ0Yvdmp6L0k9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2RzOlNpZ25lZEluZm8+PGRzOlNpZ25hdHVyZVZhbHVlPk56bU42R0RLcHNpMVU4NndaTXNjWjY2aExHNDVhMzhhMGhvaCtpdFdCTWQzNS9RMnF1Y2N2NEJaTGhSbU1xYmFIL3l4VnZ4bWUvWXExR24xbEkrVlpwZkZsYURXQnZTcXUxdWJVemVEbEtVUDdHUmVnakNSTFErSkhxZnQ2aHRDdENQdkttQ0NTaVNEVlZydmcvc0ZLVXBuVDhPWEhkK25ENDBLSVQ4NHQ2OERiM2pTN3g2amx6VDMzYk1Vdm83dVNFUDVnSnFUbG9RMVVWY280WmszUGVxK0tDOWF6TUFkVHVnMWZZRDJXVWtXOEZCd084b1ZBUWpDMGo4VkVyVVpiUUpRS2hhdTMxcjNVcU1VUExNS0NJaFZxZ0tPRVd6MWt1a1NWY2MzdTJjR0owT1FJU093N0xQbkRDSTdPclVMaGU4NEJESTMzR01JMDNXazFMNG5Mdz09PC9kczpTaWduYXR1cmVWYWx1ZT4NCjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YS8+PC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPg0KICAgICAgICA8c2FtbDpOYW1lSUQgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoxLjE6bmFtZWlkLWZvcm1hdDplbWFpbEFkZHJlc3MiPmZvb0BleGFtcGxlLmNvbTwvc2FtbDpOYW1lSUQ+DQogICAgICAgIDxzYW1sOlNlc3Npb25JbmRleD4xPC9zYW1sOlNlc3Npb25JbmRleD4NCiAgICAgIDwvc2FtbHA6TG9nb3V0UmVxdWVzdD4=",
          RelayState: "123",
        },
      },
      function (err, response) {
        if (err) return callback(err);
        callback(null, response);
      }
    );
  }

  function logoutGetIDPInitiated(callback) {
    request.get({
      followRedirect: false,
      uri: 'http://localhost:5050/logout'
    }, function (err, response) {
      if(err) return callback(err);

      callback(null, response);
    });
  }

  function assertPostResponse(response) {
    // Ensure we get a POST response,
    // this means responding with an HTML form that will self-submit.
    // The rest is covered by other tests.
    expect(response).to.be.ok;
    expect(response.statusCode).to.equal(200);
  }

  function assertRedirectResponse(response) {
    // Ensure we get a Redirect response,
    // The rest is covered by other tests.
    expect(response).to.be.ok;
    expect(response.statusCode).to.equal(302);
  }

  describe('HTTP Redirect', function () {
    describe('SP initiated - Should fail if No Issuer is present', function () {
      var logoutResultValue;

      before(function () {
        sessions.splice(0);
        sessions.push({
          serviceProviderId : 'https://foobarsupport.zendesk.com',
          nameId: 'foo@example.com',
          sessionIndex: '1',
          serviceProviderLogoutURL: 'https://example.com/logout',
          cert: sp1_credentials.cert // SP1 public Cert
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
          followRedirect: false,
          uri: 'http://localhost:5050/logout?SAMLRequest=fZFBS8QwEIXvgv%2Bh5J6a6da1hra4sAiF1YMrHrxl06kUmqRmUujPN1tXWBWdwxzmvW%2FmwZSkzDDKnXtzU3jC9wkpJLMZLMlFqdjkrXSKepJWGSQZtNxvHnYyS4UcvQtOu4GdIf8Tigh96J1lSbOt2BHwPMuEvhHXyDXEBoBrfluonKPu8sNBY76CIvqJJmwsBWVDxTIBaw4Zh9UzFFKAhOyVJS%2FoKS6PcipYfXmRnKo8HpKPMU6zTe6dNyr8nRNSWCZ9y7vFKtGofti0rUciVnfO3eGszDhgqp0pr86W%2F7q5j0hM1NgW5xpO3m%2FDL%2BJT%2B%2FGL%2BgM%3D&Signature=CUwze47fZpFBtD7YRGyAzRyTrK7l8pxsg%2BiUan8N%2FVPAOOVYXcNElksrYrpZLPSAVhZbWlQYLJjuYxicY%2FVIG%2FiGjoNlPUMiAGsb4vfBumgDeShns22fdSYZ27hF0NL3%2FI%2FcUThvz4wCwcFb6XTmY101Wbew3gLVdBcsx17YwIns52TNmMjG0wsW9KtGZ4jrrZ1kGJ0rsDf5BL4jBIT5KgZYF2u4xOo2v6ysUPf3lG4ALRWqJFdAdkOVJ%2BdUO%2B47n57G4q1YcFDwoL%2BTM%2B02qXV1QwiTyMXttQI25DX4%2BEru2rAA7LN9F3KPabINu4vV%2FF9TAU2DBHCFNArcRDa%2FsA%3D%3D&RelayState=123&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1'
        }, function (err, response){
          if(err) return done(err);
          expect(response.statusCode).to.equal(400);
          logoutResultValue = response.body;

          done();
        });
      });

      it('should respond with an Error message', function () {
        expect(logoutResultValue).to.equal('SAML Request with no issuer. Issuer is a mandatory element.');
      });
    });

    describe('SP initiated - 1 Session Participant', function () {
      var logoutResultValue, RelayState;

      before(function () {
        sessions.splice(0);
        sessions.push(sessionParticipant1);
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
          followRedirect: false,
          uri: 'http://localhost:5050/logout?SAMLRequest=fVFNS8NAEL0L%2Foew900zaa1xaIOFIgSqBysevG03Uw1md%2BPOBoq%2F3m1aoVZ0DnOY97WPnbEybYcr9%2Br68EgfPXFIdqa1jAMyF7236BQ3jFYZYgwa14v7FeZphp13wWnXihPJ%2FwrFTD40zoqkWs7FXuBlnmf6OrsiqSEuAJrKm0JNJOntZLPRNBlDEfnMPVWWg7JhLvIMphJyCeMnKDADhPxFJM%2FkOZpHOM1EeXmRHGe2D8LBwZdvIXSMo9HWuY3y3Hed8yH9JFsTv6famdnolH7u8hBLVcvkznmjwt9tIYXh0tRyO1CRjGraRV17YhZlTL%2BlnTJdSyeZB%2FNfmesoib2q%2BMRdCUfuj%2BO34oCd%2FWj5BQ%3D%3D&Signature=NkobB0DS0M4kfV89R%2Bma0wp0djNr4GW2ziVemwSvVYy2iF432qjs%2FC4Y1cZDXwuF5OxMgu4DuelS5mW3Z%2B46XXkoMVBizbd%2BIuJUFQcvLtiXHkoaEk8HVU0v5bA9TDoc9Ve7A0nUgKPciH7KTcFSr45vepyg0dMMQtarsUZeYSRPM0QlwxXKCWRQJDwGHLie5dMCZTRNUEcm9PtWZij714j11HI15u6Fp5GDnhp7mzKuAUdSIKHzNKAS2J4S8xZz9n9UTCl3uBbgfxZ3av6%2FMQf7HThxTl%2FIOmU%2FYCAN6DWWE%2BQ3Z11bgU06P39ZuLW2fRBOfIOO6iTEaAdORrdBOw%3D%3D&RelayState=123&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1'
        }, function (err, response){
          if(err) return done(err);
          expect(response.statusCode).to.equal(302);
          var qs = require('querystring');
          var i = response.headers.location.indexOf('SAMLResponse=');
          var query = qs.parse(response.headers.location.substr(i));
          var SAMLResponse = query.SAMLResponse;
          RelayState = query.RelayState;

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

      it('should return the corresponding RelayState', function () {
        expect(RelayState).to.equal('123');
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

      before(function () {
        sessions.splice(0);
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
          followRedirect: false,
          uri: 'http://localhost:5050/logout?SAMLRequest=fVFNS8NAEL0L%2Foew900zaa1xaIOFIgSqBysevG03Uw1md%2BPOBoq%2F3m1aoVZ0DnOY97WPnbEybYcr9%2Br68EgfPXFIdqa1jAMyF7236BQ3jFYZYgwa14v7FeZphp13wWnXihPJ%2FwrFTD40zoqkWs7FXuBlnmf6OrsiqSEuAJrKm0JNJOntZLPRNBlDEfnMPVWWg7JhLvIMphJyCeMnKDADhPxFJM%2FkOZpHOM1EeXmRHGe2D8LBwZdvIXSMo9HWuY3y3Hed8yH9JFsTv6famdnolH7u8hBLVcvkznmjwt9tIYXh0tRyO1CRjGraRV17YhZlTL%2BlnTJdSyeZB%2FNfmesoib2q%2BMRdCUfuj%2BO34oCd%2FWj5BQ%3D%3D&Signature=NkobB0DS0M4kfV89R%2Bma0wp0djNr4GW2ziVemwSvVYy2iF432qjs%2FC4Y1cZDXwuF5OxMgu4DuelS5mW3Z%2B46XXkoMVBizbd%2BIuJUFQcvLtiXHkoaEk8HVU0v5bA9TDoc9Ve7A0nUgKPciH7KTcFSr45vepyg0dMMQtarsUZeYSRPM0QlwxXKCWRQJDwGHLie5dMCZTRNUEcm9PtWZij714j11HI15u6Fp5GDnhp7mzKuAUdSIKHzNKAS2J4S8xZz9n9UTCl3uBbgfxZ3av6%2FMQf7HThxTl%2FIOmU%2FYCAN6DWWE%2BQ3Z11bgU06P39ZuLW2fRBOfIOO6iTEaAdORrdBOw%3D%3D&RelayState=123&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1'
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
        expect(xmlhelper.getIssueInstantUTC(sessionParticipantLogoutRequest)).to.equal(frozenTime);
        expect(xmlhelper.getDestination(sessionParticipantLogoutRequest)).to.equal(sessionParticipant2.serviceProviderLogoutURL);
        expect(xmlhelper.getConsent(sessionParticipantLogoutRequest)).to.equal('urn:oasis:names:tc:SAML:2.0:consent:unspecified');
        expect(xmlhelper.getElementText(sessionParticipantLogoutRequest, 'Issuer')).to.equal(samlIdPIssuer);
        expect(xmlhelper.getElementText(sessionParticipantLogoutRequest, 'NameID')).to.equal(sessionParticipant2.nameId);
        expect(xmlhelper.getElementText(sessionParticipantLogoutRequest, 'samlp:SessionIndex')).to.equal(sessionParticipant2.sessionIndex);
      });

      it('should validate LogoutRequest signature', function () {
        expect(SAMLRequest).to.exist;
        expect(sessionParticipantLogoutRequestRelayState).to.exist;
        expect(sessionParticipantLogoutRequestSigAlg).to.exist;
        expect(sessionParticipantLogoutRequestSignature).to.exist;

        var params = {
          query: {
            SAMLRequest: SAMLRequest,
            RelayState: sessionParticipantLogoutRequestRelayState,
            SigAlg: sessionParticipantLogoutRequestSigAlg,
            Signature: sessionParticipantLogoutRequestSignature
          }
        };

        expect(utils.validateSignature(params, "LOGOUT_REQUEST", sessionParticipantLogoutRequest, { signingCert: server.credentials.cert.toString(), deflate: true })).to.be.undefined;
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
          var EncodedAndDeflatedSAMLResponse = 'fZFBi8IwEIXv/oqSe21SbesOtrCsF8G9rOJhL0sax1VIMyGTgj9/27KCXrwEXubN92aSNevOetjRL/XxC9mTY0xunXUMU6kWfXBAmq8MTnfIEA3s3z93kM8l+ECRDFkxS5LtphY/edvqEnWBZVWdVrI6y1JPRXeHH6gWIzmkeS5NJQtMjRoOpbBM31Z6maI5L9vW4HKhVmPvEQNfydViSJxYzD1uHUft4nApVZmqPFXlQS1gUUFRfY+uDXK8Oh2nzkuMHrLMktH2QhyhkIUc5Li1aAZ3kqzHoWBih4cHeL2/ZsYwRohmjOAh40zU6sC99xTiHG+68xbnhrp19pDwkOlhH3XsuXlSH3TC5Khtj68n4MkN+94YZBbZPzh7Is/u+vmfmz8=';
          var params = {
            SAMLResponse: EncodedAndDeflatedSAMLResponse,
            RelayState: sessionParticipantLogoutRequestRelayState,
            SigAlg: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
          };

          // We need to sign the reponse here
          var signature = signers.sign({key: sp2_credentials.key, signatureAlgorithm: 'rsa-sha1' }, qs.stringify(params));
          params.Signature = signature;

          request.get({
            followRedirect: false,
            uri: 'http://localhost:5050/logout',
            qs: params
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
          expect(xmlhelper.getIssueInstantUTC(sessionParticipantLogoutResponse)).to.equal(frozenTime);
          expect(xmlhelper.getDestination(sessionParticipantLogoutResponse)).to.equal(sessionParticipant1.serviceProviderLogoutURL);
          expect(xmlhelper.getInResponseTo(sessionParticipantLogoutResponse)).to.equal('samlr-220c705e-c15e-11e6-98a4-ecf4bbce4318');
          expect(xmlhelper.getIssuer(sessionParticipantLogoutResponse)).to.equal(samlIdPIssuer);
        });

        it('should respond with a Success value', function () {
          var signedAssertion = /(<samlp:StatusCode.*\/>)/.exec(sessionParticipantLogoutResponse)[1];
          var doc = new xmldom.DOMParser().parseFromString(signedAssertion);
          var logoutResultValue = doc.documentElement.getAttribute('Value');
          expect(logoutResultValue).to.equal('urn:oasis:names:tc:SAML:2.0:status:Success');
        });

        it('should match RelayState with the one that started the logout', function(){
          expect(sessionParticipantLogoutResponseRelayState).to.equal('123');
        });

        it('should validate LogoutResponse signature', function () {
          expect(SAMLResponse).to.exist;
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

          expect(utils.validateSignature(params, "LOGOUT_RESPONSE", sessionParticipantLogoutResponse, { signingCert: server.credentials.cert.toString(), deflate: true })).to.be.undefined;
        });

        it('should remove session from sessions array', function () {
          expect(sessions.length).to.equal(0);
        });
      });
    });

    describe('SP initiated - LogoutRequest with multiple SessionIndex elements', function () {
      let logoutResultValue;

      before(function () {
        sessions.splice(0);
        sessions.push(sessionParticipant1);
      });

      // SAMLRequest: base64 encoded + deflated + URLEncoded
      // Signature: URLEncoded
      // SigAlg: URLEncoded

      // <samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="samlr-220c705e-c15e-11e6-98a4-ecf4bbce4318" IssueInstant="2016-12-13T18:01:12Z" Version="2.0">
      //   <saml:Issuer>https://foobarsupport.zendesk.com</saml:Issuer>
      //   <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">foo@example.com</saml:NameID>
      //   <samlp:SessionIndex>not-the-session-index</samlp:SessionIndex>
      //   <samlp:SessionIndex>1</samlp:SessionIndex>
      // </samlp:LogoutRequest>
      before(function (done) {
        request.get({
          followRedirect: false,
          uri: 'http://localhost:5050/logout?SAMLRequest=fZHNTsMwEIRfJfLdSTYtpazaiEoVUqTCARAHbq6zpRHxD15Hqnh63ORSocLFh9n5ZnblFSvTe9y5DzfEZ%2FoaiGN2Mr1lHCdrMQSLTnHHaJUhxqjxZfO4wyov0QcXnXa9uED%2BJxQzhdg5K7JmuxZnIMiqKvVteUNSQ3oAaCHvlmouSR%2Fm%2B72m%2BQyWyc88UGM5KhvXoiphIaGSMHuFJZaAUL2L7I0Cp%2FA0zktRr87xOHKhPsboGYvi4NxeBR68dyHm32Rb4s9cO7MqLu0T%2B5QOaLbZgwtGxb8vgxxGpWvlYbQiGdX1m7YNxCzq1HlPJ2V8TxdNU%2FjU5PElOdPqTdrnVFsXZTyS5EmU3VmdsF%2FOazRcdxZX%2Frr%2BAQ%3D%3D&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256&Signature=39NSgctst5GtoKkCh4yKFPm4t8v0lhLdYpS14hlsi%2FLRbRDz8GFuDLlR6OILVZy%2BdY9RwQKtaF7lZfkF7EyJ5Ip4EELojxNA4dVcn6%2Bl%2B0fRXUHQppoBEACzKH%2BZJVW3OL5cmKEMvPyM5H81oslBvgkSbX3XTr%2FhPLtmLpRzmo2R%2Fp6Igqdc6Lfo0Hj3WmjkiKh%2F3C%2F0w1sRLAI5KdojEXHuoaS10QxBJq2dUwHpMONP4PnD1M5Gq1Jq%2F3PafXC7KBIretam86Lau96anMWWqT60j05eXtPAew66ZFGmeXgRqPcEGat6flcJaDHmVgWjqY7gJHPP6XTBadnng3vIdQ%3D%3D'
        }, function (err, response){
          if(err) return done(err);
          expect(response.statusCode).to.equal(302);
          const qs = require('querystring');
          const i = response.headers.location.indexOf('SAMLResponse=');
          const query = qs.parse(response.headers.location.substr(i));
          const SAMLResponse = query.SAMLResponse;

          zlib.inflateRaw(Buffer.from(SAMLResponse, 'base64'), function (err, decodedAndInflated) {
            if(err) return done(err);
            signedAssertion = /(<samlp:StatusCode.*\/>)/.exec(decodedAndInflated)[1];
            const doc = new xmldom.DOMParser().parseFromString(signedAssertion);
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

    describe('SP initiated - Invalid signature', function () {
      var response;

      before(function () {
        sessions.splice(0);
        sessions.push(sessionParticipant1);
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
          uri: 'http://localhost:5050/logout?SAMLRequest=fZFPS8NAEMXv%2FRRh75tm0lrr0AYLRQhUD1Y8eNtuphrM%2FnFnA8VP7zbFUgW97OHN782bxy5Ymc7jxr26Pj7SR08cs4PpLOMwWYo%2BWHSKW0arDDFGjdvV%2FQbLvEAfXHTadeLC8r9DMVOIrbMiq9dLcTQEWZaFvi6uSGpIDwDN5M1cTSXp%2FXS30zSdwDzxzD3VlqOycSnKAmYSSgmTJ5hjAQjli8ieKXBansZ5IapRli2OCThYQ%2FUWo2ccj%2FfO7VTg3nsXYv5JtiF%2Bz7Uzi%2FElfrY%2FpBr1Ortzwaj4dz%2FIYVDaRu4HFMmotls1TSBmUaXYWzoo4zu6CDstP4d53CY4dajTVYcKTtQvdfSt%2Fvi36gs%3D&Signature=asidjpasjdpasjndoubvuojewprjweprj&RelayState=123&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1'
        }, function (err, res){
          if(err) return done(err);
          response = res;
          done();
        });
      });

      it('should return invalid signture error', function(){
        expect(response.statusCode).to.equal(400);
        expect(response.body).to.equal('Signature check errors: The signature provided (asidjpasjdpasjndoubvuojewprjweprj) does not match the one calculated');
      });
    });

    describe('SP initiated - Session Index does not match an active session', function () {
      var response;

      before(function () {
        sessions.splice(0);
        sessions.push(sessionParticipant1);
      });

      // SAMLRequest: base64 encoded + deflated + URLEncoded
      // Signature: URLEncoded
      // SigAlg: URLEncoded

      // <samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="samlr-220c705e-c15e-11e6-98a4-ecf4bbce4318" IssueInstant="2016-12-13T18:01:12Z" Version="2.0">
      //   <saml:Issuer>https://foobarsupport.zendesk.com</saml:Issuer>
      //   <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">foo@example.com</saml:NameID>
      //   <saml:SessionIndex>123</saml:SessionIndex>
      // </samlp:LogoutRequest>
      before(function (done) {
        request.get({
          jar: request.jar(),
          followRedirect: false,
          uri: 'http://localhost:5050/logout?SAMLRequest=fZFBSwMxEIXv%2FRVL7tnupLXWoV0sFGGherDiwVuaneriJlkzWSj%2BetOtaBX0ksOb782bRxasbdvhxj%2F7Pt7TW08cs4NtHeMwWYo%2BOPSaG0anLTFGg9vV7QZVXmAXfPTGt%2BLM8r9DM1OIjXciq9ZLcTQEqVRhLosLkgbSA0AzeTXXU0lmP93tDE0nME88c0%2BV46hdXApVwEyCkjB5gDkWgKCeRPZIgdPyNM4LUY6ybHFMwMEaypcYO8bxeO%2F9Tgfuu86HmL%2BTq4lfc%2BPtYnyOf9nvUo1qnd34YHX8ux%2FkMChNLfcDimR1067qOhCzKFPsNR207Vo6Czst%2Fw7bJjZVqNJRhxLU5BP7IY9O4q9%2FKz8A&Signature=asidjpasjdpasjndoubvuojewprjweprj&RelayState=123&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1'
        }, function (err, res){
          if(err) return done(err);
          response = res;
          done();
        });
      });

      it('should return invalid session participant', function(){
        expect(response.statusCode).to.equal(400);
        expect(response.body).to.equal('Invalid Session Participant');
      });
    });

    describe('SP initiated - NameID does not match an active session', function () {
      var response;

      before(function () {
        sessions.splice(0);
        sessions.push(sessionParticipant1);
      });

      // SAMLRequest: base64 encoded + deflated + URLEncoded
      // Signature: URLEncoded
      // SigAlg: URLEncoded

      // <samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="samlr-220c705e-c15e-11e6-98a4-ecf4bbce4318" IssueInstant="2016-12-13T18:01:12Z" Version="2.0">
      //   <saml:Issuer>https://foobarsupport.zendesk.com</saml:Issuer>
      //   <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">bar@example.com</saml:NameID>
      //   <saml:SessionIndex>1</saml:SessionIndex>
      // </samlp:LogoutRequest>
      before(function (done) {
        request.get({
          jar: request.jar(),
          followRedirect: false,
          uri: 'http://localhost:5050/logout?SAMLRequest=fZHBTsMwEETv%2FYrId6fZNJSyaiMqVUiRCgeKOHBznS1ExHbwOlLF1%2BOmCAISXHyYfbOzIy9ZmbbDrXt2fbint544JEfTWsZhshK9t%2BgUN4xWGWIMGnfr2y3maYadd8Fp14qR5X%2BHYiYfGmdFUm1W4mTwMs8zfZldkNQQHwCay6uFKiTpQ7HfaypmsIg8c0%2BV5aBsWIk8g7mEXMLsARaYAUL%2BJJJH8hyXx3GaiXKSJMtTAg5WX76E0DFOpwfn9spz33XOh%2FSdbE38mmpnltMx%2FmW%2FizWqTXLjvFHh736QwqA0tTwMKJJRTbuua0%2FMooyZ13RUpmtpFHZe%2Fh22i2ysUMWjjiV8Qj%2FEyVn89WvlBw%3D%3D&Signature=asidjpasjdpasjndoubvuojewprjweprj&RelayState=123&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1'
        }, function (err, res){
          if(err) return done(err);
          response = res;
          done();
        });
      });

      it('should return invalid session participant', function(){
        expect(response.statusCode).to.equal(400);
        expect(response.body).to.equal('Invalid Session Participant');
      });
    });

    // IdP Initiated with no Session Participants should not happen
    // At least we should have 1 session participant. Still should not return an error
    describe('IdP initiated - No Session Participants', function () {
      var body;

      before(function () {
        sessions.splice(0);
      });

      before(function (done) {
        request.get({
          jar: request.jar(),
          followRedirect: false,
          uri: 'http://localhost:5050/logout'
        }, function (err, response) {
          if(err) return done(err);
          expect(response.statusCode).to.equal(200);
          body = response.body;

          done();
        });
      });

      it('should respond with a Success value', function () {
        expect(body).to.equal('OK');
      });
    });

    describe('IdP initiated - 1 Session Participant', function () {
      var SAMLRequest;
      var sessionParticipantLogoutRequest;
      var sessionParticipantLogoutRequestSigAlg;
      var sessionParticipantLogoutRequestSignature;
      var sessionParticipantLogoutRequestRelayState;

      before(function () {
        sessions.splice(0);
        sessions.push(sessionParticipant1);
      });

      before(function (done) {
        request.get({
          followRedirect: false,
          uri: 'http://localhost:5050/logout'
        }, function (err, response) {
          if(err) return done(err);
          expect(response.statusCode).to.equal(302);

          var i = response.headers.location.indexOf('?');
          var completeQueryString = response.headers.location.substr(i+1);
          var parsedQueryString = qs.parse(completeQueryString);

          SAMLRequest = parsedQueryString.SAMLRequest;
          sessionParticipantLogoutRequestSigAlg = parsedQueryString.SigAlg;
          sessionParticipantLogoutRequestSignature = parsedQueryString.Signature;
          sessionParticipantLogoutRequestRelayState = parsedQueryString.RelayState;

          zlib.inflateRaw(new Buffer(SAMLRequest, 'base64'), function (err, decodedAndInflated) {
            if(err) return done(err);
            sessionParticipantLogoutRequest = decodedAndInflated.toString();

            done();
          });
        });
      });

      it('should validate LogoutRequest to Session Participant', function () {
        expect(sessionParticipantLogoutRequest).to.exist;
        expect(xmlhelper.getIssueInstantUTC(sessionParticipantLogoutRequest)).to.equal(frozenTime);
        expect(xmlhelper.getDestination(sessionParticipantLogoutRequest)).to.equal(sessionParticipant1.serviceProviderLogoutURL);
        expect(xmlhelper.getConsent(sessionParticipantLogoutRequest)).to.equal('urn:oasis:names:tc:SAML:2.0:consent:unspecified');
        expect(xmlhelper.getElementText(sessionParticipantLogoutRequest, 'Issuer')).to.equal(samlIdPIssuer);
        expect(xmlhelper.getElementText(sessionParticipantLogoutRequest, 'NameID')).to.equal(sessionParticipant1.nameId);
        expect(xmlhelper.getElementText(sessionParticipantLogoutRequest, 'samlp:SessionIndex')).to.equal(sessionParticipant1.sessionIndex);
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

        expect(utils.validateSignature(params, "LOGOUT_REQUEST", sessionParticipantLogoutRequest, { signingCert: server.credentials.cert.toString(), deflate: true })).to.be.undefined;
      });
    });

    describe('IdP initiated - 2 Session Participant', function () {
      var SAMLRequest;
      var sessionParticipantLogoutRequest;
      var sessionParticipantLogoutRequestSigAlg;
      var sessionParticipantLogoutRequestSignature;
      var sessionParticipantLogoutRequestRelayState;

      before(function () {
        sessions.splice(0);
        sessions.push(sessionParticipant1);
        sessions.push(sessionParticipant2);
      });

      before(function (done) {
        request.get({
          followRedirect: false,
          uri: 'http://localhost:5050/logout'
        }, function (err, response) {
          if(err) return done(err);

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
        expect(xmlhelper.getIssueInstantUTC(sessionParticipantLogoutRequest)).to.equal(frozenTime);
        expect(xmlhelper.getDestination(sessionParticipantLogoutRequest)).to.equal(sessionParticipant1.serviceProviderLogoutURL);
        expect(xmlhelper.getConsent(sessionParticipantLogoutRequest)).to.equal('urn:oasis:names:tc:SAML:2.0:consent:unspecified');
        expect(xmlhelper.getElementText(sessionParticipantLogoutRequest, 'Issuer')).to.equal(samlIdPIssuer);
        expect(xmlhelper.getElementText(sessionParticipantLogoutRequest, 'NameID')).to.equal(sessionParticipant1.nameId);
        expect(xmlhelper.getNameIdentifierFormat(sessionParticipantLogoutRequest)).to.equal(sessionParticipant1.nameIdFormat);
        expect(xmlhelper.getElementText(sessionParticipantLogoutRequest, 'samlp:SessionIndex')).to.equal(sessionParticipant1.sessionIndex);
      });

      it('should validate LogoutRequest signature', function () {
        expect(SAMLRequest).to.exist;
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

        expect(utils.validateSignature(params, "LOGOUT_REQUEST", sessionParticipantLogoutRequest, { signingCert: server.credentials.cert.toString(), deflate: true })).to.be.undefined;
      });

      describe('should send Session Participant 1 LogoutResponse to the SAML IdP', function () {
        var SAMLRequest2;
        var sessionParticipant2LogoutRequest;
        var sessionParticipant2LogoutRequestRelayState;
        var sessionParticipant2LogoutRequestSigAlg;
        var sessionParticipant2LogoutRequestSignature;

        before(function (done) {
          // SAMLResponse: base64 encoded + deflated + URLEncoded
          // Signature: URLEncoded
          // SigAlg: URLEncoded
          //
          // <samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
          //   ID="_2bba6ea5e677d807f06a"
          //   InResponseTo="_73dda80c6c1262377f52"
          //   Version="2.0"
          //   IssueInstant="2016-12-28T13:14:14Z"
          //   Destination="http://localhost:5050/logout">
          //     <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://foobarsupport.zendesk.com</saml:Issuer>
          //     <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
          //     </samlp:Status>
          // </samlp:LogoutResponse>
          var EncodedAndDeflatedSAMLResponse = 'fZHNasMwEITveQqje2JZqe0gEkNpLoH00oQceikbefNDba3QSlD69JVNA8kloMtoZ7/RoCVD3zm9pTPF8IHsyDJmP31nWY+jlYjeagK+srbQI+tg9O71favVTGrnKZChTkyybLNeiS91PEKFUGJV1+1C1idZwTi0N/iekq2ety0spKlMoSo1r+tTqQbbAT1fya5Ego9rzBE3lgPYkC5lUU0LNVWLfTHXxUs6n4NrjRyuFsK4eQnB6TzvyEB3IQ66lKVMcigomuTOsuXQTI9sf9f1eVVgRj9EiGaI4JRxIjqC5+gc+TD7Rdsif88M9cv8LuEu0+ldgBC5eVBv1GJ2gC7i8xfw6Na7aAwyi/wfnD+QJzf9+KXNHw==';
          var params = {
            SAMLResponse: EncodedAndDeflatedSAMLResponse,
            RelayState: sessionParticipantLogoutRequestRelayState,
            SigAlg: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
          };

          // We need to sign the reponse here
          var signature = signers.sign({key: sp1_credentials.key, signatureAlgorithm: 'rsa-sha1' }, qs.stringify(params));
          params.Signature = signature;

          request.get({
            followRedirect: false,
            uri: 'http://localhost:5050/logout',
            qs: params
          }, function (err, response) {
            if (err) { return done(err); }
            expect(response.statusCode).to.equal(302);

            var i = response.headers.location.indexOf('?');
            var completeQueryString = response.headers.location.substr(i+1);
            var parsedQueryString = qs.parse(completeQueryString);

            SAMLRequest2 = parsedQueryString.SAMLRequest;
            sessionParticipant2LogoutRequestRelayState = parsedQueryString.RelayState;
            sessionParticipant2LogoutRequestSigAlg = parsedQueryString.SigAlg;
            sessionParticipant2LogoutRequestSignature = parsedQueryString.Signature;

            zlib.inflateRaw(new Buffer(SAMLRequest2, 'base64'), function (err, decodedAndInflated) {
              if(err) return done(err);
              sessionParticipant2LogoutRequest = decodedAndInflated.toString();

              done();
            });
          });
        });

        it('should validate LogoutRequest to Session Participant 2', function () {
          expect(sessionParticipant2LogoutRequest).to.exist;
          expect(xmlhelper.getIssueInstantUTC(sessionParticipant2LogoutRequest)).to.equal(frozenTime);
          expect(xmlhelper.getDestination(sessionParticipant2LogoutRequest)).to.equal(sessionParticipant2.serviceProviderLogoutURL);
          expect(xmlhelper.getConsent(sessionParticipant2LogoutRequest)).to.equal('urn:oasis:names:tc:SAML:2.0:consent:unspecified');
          expect(xmlhelper.getElementText(sessionParticipant2LogoutRequest, 'Issuer')).to.equal(samlIdPIssuer);
          expect(xmlhelper.getElementText(sessionParticipant2LogoutRequest, 'NameID')).to.equal(sessionParticipant2.nameId);
          expect(xmlhelper.getElementText(sessionParticipant2LogoutRequest, 'samlp:SessionIndex')).to.equal(sessionParticipant2.sessionIndex);
        });

        it('should validate LogoutRequest signature', function () {
          expect(SAMLRequest2).to.exist;
          expect(sessionParticipant2LogoutRequestRelayState).to.exist;
          expect(sessionParticipant2LogoutRequestSigAlg).to.exist;
          expect(sessionParticipant2LogoutRequestSignature).to.exist;
          var params =  {
            query: {
              SAMLRequest: SAMLRequest2,
              RelayState: sessionParticipant2LogoutRequestRelayState,
              SigAlg: sessionParticipant2LogoutRequestSigAlg,
              Signature: sessionParticipant2LogoutRequestSignature
            }
          };

          expect(utils.validateSignature(params, "LOGOUT_REQUEST", sessionParticipant2LogoutRequest, { signingCert: server.credentials.cert.toString(), deflate: true })).to.be.undefined;
        });
      });
    });

    describe('SP initiated - When the SessionParticipant does not have a configured serviceProviderLogoutURL', function () {
      before(function () {
        sessions.splice(0);
        const sessionParticipantWithoutDestination = { ...sessionParticipant1 };
        delete sessionParticipantWithoutDestination.serviceProviderLogoutURL;
        sessions.push(sessionParticipantWithoutDestination);
      });

      // SAMLRequest: base64 encoded + deflated + URLEncoded
      // Signature: URLEncoded
      // SigAlg: URLEncoded

      // <samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="samlr-220c705e-c15e-11e6-98a4-ecf4bbce4318" IssueInstant="2016-12-13T18:01:12Z" Version="2.0">
      //   <saml:Issuer>https://foobarsupport.zendesk.com</saml:Issuer>
      //   <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">foo@example.com</saml:NameID>
      //   <saml:SessionIndex>1</saml:SessionIndex>
      // </samlp:LogoutRequest>
      it('should respond with an error', function (done) {
        request.get({
          followRedirect: false,
          uri: 'http://localhost:5050/logout?SAMLRequest=fVFNS8NAEL0L%2Foew900zaa1xaIOFIgSqBysevG03Uw1md%2BPOBoq%2F3m1aoVZ0DnOY97WPnbEybYcr9%2Br68EgfPXFIdqa1jAMyF7236BQ3jFYZYgwa14v7FeZphp13wWnXihPJ%2FwrFTD40zoqkWs7FXuBlnmf6OrsiqSEuAJrKm0JNJOntZLPRNBlDEfnMPVWWg7JhLvIMphJyCeMnKDADhPxFJM%2FkOZpHOM1EeXmRHGe2D8LBwZdvIXSMo9HWuY3y3Hed8yH9JFsTv6famdnolH7u8hBLVcvkznmjwt9tIYXh0tRyO1CRjGraRV17YhZlTL%2BlnTJdSyeZB%2FNfmesoib2q%2BMRdCUfuj%2BO34oCd%2FWj5BQ%3D%3D&Signature=NkobB0DS0M4kfV89R%2Bma0wp0djNr4GW2ziVemwSvVYy2iF432qjs%2FC4Y1cZDXwuF5OxMgu4DuelS5mW3Z%2B46XXkoMVBizbd%2BIuJUFQcvLtiXHkoaEk8HVU0v5bA9TDoc9Ve7A0nUgKPciH7KTcFSr45vepyg0dMMQtarsUZeYSRPM0QlwxXKCWRQJDwGHLie5dMCZTRNUEcm9PtWZij714j11HI15u6Fp5GDnhp7mzKuAUdSIKHzNKAS2J4S8xZz9n9UTCl3uBbgfxZ3av6%2FMQf7HThxTl%2FIOmU%2FYCAN6DWWE%2BQ3Z11bgU06P39ZuLW2fRBOfIOO6iTEaAdORrdBOw%3D%3D&RelayState=123&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1'
        }, (err, response) => {
          if (err) return done(err);
          expect(response.statusCode).to.equal(400);
          expect(response.body).to.equal('The logout URL may be missing or misconfigured');
          done();
        });
      });
    });

    describe('SP initiated - 1 Session Participant with POST binding', function () {
      var logoutResponse;

      before(function () {
        prepareOneParticipant(BINDINGS.HTTP_POST);
      });

      before(function (done) {
        logoutGetSPInitiated(function(err, response){
          if (err) return done(err);
          logoutResponse = response;
          done();
        });
      });

      it('Should return POST request', function () {
        assertPostResponse(logoutResponse);
      });
    });

    describe('SP initiated - 2 Session Participants with POST binding', function() {
      var logoutResponse;

      before(function () {
        prepareTwoParticipants(BINDINGS.HTTP_POST);
      });

      before(function (done) {
        logoutGetSPInitiated(function(err, response){
          if (err) return done(err);
          logoutResponse = response;
          done();
        });
      });

      it('Should return POST request', function () {
        assertPostResponse(logoutResponse);
      });
    });

    describe('IDP initiated - 1 Session Participant with POST binding', function() {
      var logoutResponse;

      before(function () {
       prepareOneParticipant(BINDINGS.HTTP_POST);
      });

      before(function (done) {
        logoutGetIDPInitiated(function(err, response){
          if (err) return done(err);
          logoutResponse = response;
          done();
        });
      });

      it('Should return POST request', function () {
        assertPostResponse(logoutResponse);
      });
    });
  });

  describe('HTTP POST', function () {
    describe('SP initiated - Should fail if No Issuer is present', function () {
      var logoutResultValue;

      before(function () {
        sessions.splice(0);
        sessions.push(sessionParticipant1);
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
          followRedirect: false,
          uri: 'http://localhost:5050/logout',
          json: true,
          body: {
            SAMLRequest: 'PHNhbWxwOkxvZ291dFJlcXVlc3QgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgSUQ9InBmeDRjNTk4YmRhLWQ0ZWYtNTdkOC04NDM1LTk1ZmNmYzE4Y2I0NyIgSXNzdWVJbnN0YW50PSIyMDE2LTEyLTEzVDE4OjAxOjEyWiIgVmVyc2lvbj0iMi4wIj48ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj4NCiAgPGRzOlNpZ25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz4NCiAgICA8ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3JzYS1zaGExIi8+DQogIDxkczpSZWZlcmVuY2UgVVJJPSIjcGZ4NGM1OThiZGEtZDRlZi01N2Q4LTg0MzUtOTVmY2ZjMThjYjQ3Ij48ZHM6VHJhbnNmb3Jtcz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PC9kczpUcmFuc2Zvcm1zPjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjc2hhMSIvPjxkczpEaWdlc3RWYWx1ZT5oakVEWXBPeU96SnBlMzZkcUFLUFRFMENFYXc9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2RzOlNpZ25lZEluZm8+PGRzOlNpZ25hdHVyZVZhbHVlPmU4TDJOeEx4RjJwMjYrU0NUZnQyMnNja2F1emk5aXlHNTNwRkgvaFlqUEZ5SFU2eTRjcjN0bnFzZklzWHlTR0xwaHUvam9nMWRTVVRFMWpxV0s3U0pZeVJFK1hOM1pwb2I0cDQ3eFAxZGZveFhSd2lNQXRab1hWaWpFYXp1QmxteEZCRjV5dTl6cnFMcFlsY1lRMWRSdmY5dkp0bzVHOXNES3VaeXZFNkVxNG8rZDRPNW9iUmxpWDE5dGovMEFIUzNtcHJOR0QwVlYvU3BhUzVXMzZqMEM3aW4zNG5JRHpBdUc2RUJXVkp1SllzQXp3R0wwOVV6TlhzVTNuMVZIaHhaeUN5Zlo2TEJFNFJvc3ZvaTNiZzZ5cE56dXVFek82bGxndlFRRnFiS1h4NmpGT2I2WU1LWXRMdytobWMyZUlmazBvOUVaSzBUaTlMYU93M09oSU5rUT09PC9kczpTaWduYXR1cmVWYWx1ZT4NCjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YS8+PC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPg0KICAgICAgICA8c2FtbDpOYW1lSUQgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoxLjE6bmFtZWlkLWZvcm1hdDplbWFpbEFkZHJlc3MiPmZvb0BleGFtcGxlLmNvbTwvc2FtbDpOYW1lSUQ+DQogICAgICAgIDxzYW1sOlNlc3Npb25JbmRleD4xPC9zYW1sOlNlc3Npb25JbmRleD4NCiAgICAgIDwvc2FtbHA6TG9nb3V0UmVxdWVzdD4=',
            RelayState: '123'
          }
        }, function (err, response){
          if (err) { return done(err); }
          expect(response.statusCode).to.equal(400);
          logoutResultValue = response.body;

          done();
        });
      });

      it('should respond with an Error message', function () {
        expect(logoutResultValue).to.equal('SAML Request with no issuer. Issuer is a mandatory element.');
      });
    });

    describe('SP initiated - 1 Session Participant', function () {
      var logoutResultValue, relayState, samlResponse;

      before(function () {
        sessions.splice(0);
        sessions.push(sessionParticipant1);
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
          followRedirect: false,
          uri: 'http://localhost:5050/logout',
          json: true,
          body: {
            SAMLRequest: 'PD94bWwgdmVyc2lvbj0iMS4wIj8+DQo8c2FtbHA6TG9nb3V0UmVxdWVzdCB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0icGZ4NmZlNjU3ZTMtMWE3Zi04OTNlLWY2OTAtZjdmYzUxNjJlYTExIiBJc3N1ZUluc3RhbnQ9IjIwMTYtMTItMTNUMTg6MDE6MTJaIiBWZXJzaW9uPSIyLjAiPg0KICAgICAgICA8c2FtbDpJc3N1ZXI+aHR0cHM6Ly9mb29iYXJzdXBwb3J0LnplbmRlc2suY29tPC9zYW1sOklzc3Vlcj48ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj4NCiAgPGRzOlNpZ25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz4NCiAgICA8ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3JzYS1zaGExIi8+DQogIDxkczpSZWZlcmVuY2UgVVJJPSIjcGZ4NmZlNjU3ZTMtMWE3Zi04OTNlLWY2OTAtZjdmYzUxNjJlYTExIj48ZHM6VHJhbnNmb3Jtcz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PC9kczpUcmFuc2Zvcm1zPjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjc2hhMSIvPjxkczpEaWdlc3RWYWx1ZT55SnpIbmRqL3NuaVJzTG1kcHFSZ0Yvdmp6L0k9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2RzOlNpZ25lZEluZm8+PGRzOlNpZ25hdHVyZVZhbHVlPk56bU42R0RLcHNpMVU4NndaTXNjWjY2aExHNDVhMzhhMGhvaCtpdFdCTWQzNS9RMnF1Y2N2NEJaTGhSbU1xYmFIL3l4VnZ4bWUvWXExR24xbEkrVlpwZkZsYURXQnZTcXUxdWJVemVEbEtVUDdHUmVnakNSTFErSkhxZnQ2aHRDdENQdkttQ0NTaVNEVlZydmcvc0ZLVXBuVDhPWEhkK25ENDBLSVQ4NHQ2OERiM2pTN3g2amx6VDMzYk1Vdm83dVNFUDVnSnFUbG9RMVVWY280WmszUGVxK0tDOWF6TUFkVHVnMWZZRDJXVWtXOEZCd084b1ZBUWpDMGo4VkVyVVpiUUpRS2hhdTMxcjNVcU1VUExNS0NJaFZxZ0tPRVd6MWt1a1NWY2MzdTJjR0owT1FJU093N0xQbkRDSTdPclVMaGU4NEJESTMzR01JMDNXazFMNG5Mdz09PC9kczpTaWduYXR1cmVWYWx1ZT4NCjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YS8+PC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPg0KICAgICAgICA8c2FtbDpOYW1lSUQgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoxLjE6bmFtZWlkLWZvcm1hdDplbWFpbEFkZHJlc3MiPmZvb0BleGFtcGxlLmNvbTwvc2FtbDpOYW1lSUQ+DQogICAgICAgIDxzYW1sOlNlc3Npb25JbmRleD4xPC9zYW1sOlNlc3Npb25JbmRleD4NCiAgICAgIDwvc2FtbHA6TG9nb3V0UmVxdWVzdD4=',
            RelayState: '123'
          }
        }, function (err, response){
          if (err) { return done(err); }
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

      before(function () {
        sessions.splice(0);
        sessions.push(sessionParticipant1);
        sessions.push(sessionParticipant2);
      });

      // <samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="samlr-220c705e-c15e-11e6-98a4-ecf4bbce4318" IssueInstant="2016-12-13T18:01:12Z" Version="2.0">
      //   <saml:Issuer>https://foobarsupport.zendesk.com</saml:Issuer>
      //   <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">foo@example.com</saml:NameID>
      //   <saml:SessionIndex>1</saml:SessionIndex>
      // </samlp:LogoutRequest>
      before(function (done) {
        // Session Participant 1 initiating logout. Sending LogoutRequest to IdP
        request.post({
          followRedirect: false,
          uri: 'http://localhost:5050/logout',
          json: true,
          body: {
            SAMLRequest: 'PD94bWwgdmVyc2lvbj0iMS4wIj8+DQo8c2FtbHA6TG9nb3V0UmVxdWVzdCB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0icGZ4NmZlNjU3ZTMtMWE3Zi04OTNlLWY2OTAtZjdmYzUxNjJlYTExIiBJc3N1ZUluc3RhbnQ9IjIwMTYtMTItMTNUMTg6MDE6MTJaIiBWZXJzaW9uPSIyLjAiPg0KICAgICAgICA8c2FtbDpJc3N1ZXI+aHR0cHM6Ly9mb29iYXJzdXBwb3J0LnplbmRlc2suY29tPC9zYW1sOklzc3Vlcj48ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj4NCiAgPGRzOlNpZ25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz4NCiAgICA8ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3JzYS1zaGExIi8+DQogIDxkczpSZWZlcmVuY2UgVVJJPSIjcGZ4NmZlNjU3ZTMtMWE3Zi04OTNlLWY2OTAtZjdmYzUxNjJlYTExIj48ZHM6VHJhbnNmb3Jtcz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PC9kczpUcmFuc2Zvcm1zPjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjc2hhMSIvPjxkczpEaWdlc3RWYWx1ZT55SnpIbmRqL3NuaVJzTG1kcHFSZ0Yvdmp6L0k9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2RzOlNpZ25lZEluZm8+PGRzOlNpZ25hdHVyZVZhbHVlPk56bU42R0RLcHNpMVU4NndaTXNjWjY2aExHNDVhMzhhMGhvaCtpdFdCTWQzNS9RMnF1Y2N2NEJaTGhSbU1xYmFIL3l4VnZ4bWUvWXExR24xbEkrVlpwZkZsYURXQnZTcXUxdWJVemVEbEtVUDdHUmVnakNSTFErSkhxZnQ2aHRDdENQdkttQ0NTaVNEVlZydmcvc0ZLVXBuVDhPWEhkK25ENDBLSVQ4NHQ2OERiM2pTN3g2amx6VDMzYk1Vdm83dVNFUDVnSnFUbG9RMVVWY280WmszUGVxK0tDOWF6TUFkVHVnMWZZRDJXVWtXOEZCd084b1ZBUWpDMGo4VkVyVVpiUUpRS2hhdTMxcjNVcU1VUExNS0NJaFZxZ0tPRVd6MWt1a1NWY2MzdTJjR0owT1FJU093N0xQbkRDSTdPclVMaGU4NEJESTMzR01JMDNXazFMNG5Mdz09PC9kczpTaWduYXR1cmVWYWx1ZT4NCjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YS8+PC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPg0KICAgICAgICA8c2FtbDpOYW1lSUQgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoxLjE6bmFtZWlkLWZvcm1hdDplbWFpbEFkZHJlc3MiPmZvb0BleGFtcGxlLmNvbTwvc2FtbDpOYW1lSUQ+DQogICAgICAgIDxzYW1sOlNlc3Npb25JbmRleD4xPC9zYW1sOlNlc3Npb25JbmRleD4NCiAgICAgIDwvc2FtbHA6TG9nb3V0UmVxdWVzdD4=',
            RelayState: '123'
          }
        }, function (err, response){
          if(err) return done(err);
          // The response contains an HTTP Form that will be submitted to Session Participant 2
          // The Form includes a LogoutRequest signed by the IdP
          expect(response.statusCode).to.equal(200);
          $ = cheerio.load(response.body);
          SAMLRequest = $('input[name="SAMLRequest"]').attr('value');
          sessionParticipantLogoutRequestRelayState = $('input[name="RelayState"]').attr('value');
          sessionParticipantLogoutRequest = new Buffer(SAMLRequest, 'base64').toString();
          done();
        });
      });

      it('should validate LogoutRequest to Session Participant', function () {
        expect(sessionParticipantLogoutRequest).to.exist;
        expect(xmlhelper.getIssueInstantUTC(sessionParticipantLogoutRequest)).to.equal(frozenTime);
        expect(xmlhelper.getDestination(sessionParticipantLogoutRequest)).to.equal(sessionParticipant2.serviceProviderLogoutURL);
        expect(xmlhelper.getConsent(sessionParticipantLogoutRequest)).to.equal('urn:oasis:names:tc:SAML:2.0:consent:unspecified');
        expect(xmlhelper.getElementText(sessionParticipantLogoutRequest, 'Issuer')).to.equal(samlIdPIssuer);
        expect(xmlhelper.getElementText(sessionParticipantLogoutRequest, 'NameID')).to.equal(sessionParticipant2.nameId);
        expect(xmlhelper.getNameIdentifierFormat(sessionParticipantLogoutRequest)).to.equal(sessionParticipant2.nameIdFormat);
        expect(xmlhelper.getElementText(sessionParticipantLogoutRequest, 'samlp:SessionIndex')).to.equal(sessionParticipant2.sessionIndex);
      });

      it('should validate LogoutRequest signature', function () {
        expect(SAMLRequest).to.exist;
        expect(sessionParticipantLogoutRequestRelayState).to.exist;

        // TODO: Review as we need to merge validation methods
        var doc = new xmldom.DOMParser().parseFromString(sessionParticipantLogoutRequest);
        expect(utils.validateSignature({body : { SAMLRequest: SAMLRequest }}, "LOGOUT_REQUEST", doc, { signingCert: server.credentials.cert })).to.be.undefined;
      });

      describe('should send Session Participant 2 LogoutResponse to the SAML IdP', function () {
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
            followRedirect: false,
            uri: 'http://localhost:5050/logout',
            json: true,
            body: {
              SAMLResponse: 'PHNhbWxwOkxvZ291dFJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIElEPSJfMmJiYTZlYTVlNjc3ZDgwN2YwNmEiIEluUmVzcG9uc2VUbz0ic2FtbHItMjIwYzcwNWUtYzE1ZS0xMWU2LTk4YTQtZWNmNGJiY2U0MzE4IiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAxNi0xMi0xNlQxMzozNzo1N1oiIERlc3RpbmF0aW9uPSJodHRwOi8vbG9jYWxob3N0OjUwNTAvbG9nb3V0Ij4KICAgIDxzYW1sOklzc3VlciB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj5odHRwczovL2Zvb2JhcnN1cHBvcnQuZXhhbXBsZS5jb208L3NhbWw6SXNzdWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI3JzYS1zaGEyNTYiLz48ZHM6UmVmZXJlbmNlIFVSST0iI18yYmJhNmVhNWU2NzdkODA3ZjA2YSI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHM6VHJhbnNmb3Jtcz48ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjc2hhMjU2Ii8+PGRzOkRpZ2VzdFZhbHVlPkxXUmUrbGNNR0VRYTlPYjlsc0hpUk5Ob29pUDgyM2JwVFA2OFVXMUdRR0U9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2RzOlNpZ25lZEluZm8+PGRzOlNpZ25hdHVyZVZhbHVlPkJoaDlMZmt3bnRaL2lBTzJvNDliWXRWZG02UTlRbjNQbDZ0Ulh2a0pKMFU2RWtWOHFaMzB6Z2JnZ21wK3c0a1U5TU1GL1d3ZVBzMDZ0VXd6Ny83bTU5VitYaVl0Um5BYk5QRUtvU29vT2FKZE9yMzc5YlU0ano4S1dZVzJWY1RnVUw2dndTaGhzczVIaFlIZ3ZxbHpnVU9iN1ZIejJuUnhLM1RvSWl3VVF2RWs1WFNQeXJUejU2TG9neTMxczgyODNBR2tBcm5jdTBPYzh5ckN6bTlCOFN1aXR4YVVORW5yV2lwcTFOTTQ4TE5LQUhCNFRlOHFIYm5pTW51VDRRc2VFVVhJTk9QVzJzWDBlcnFtOEI2c3RsTFdwaWwva2hYbGliZk5lTjE4MWVUbW5QUDlDR2t3N0ZuTm56UzNQUDlQYTJ5bU9rRG9lSkRSQy9GQ294bVFXdz09PC9kczpTaWduYXR1cmVWYWx1ZT48ZHM6S2V5SW5mbz48ZHM6WDUwOURhdGEvPjwvZHM6S2V5SW5mbz48L2RzOlNpZ25hdHVyZT4KICAgIDxzYW1scDpTdGF0dXM+PHNhbWxwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIvPgogICAgPC9zYW1scDpTdGF0dXM+Cjwvc2FtbHA6TG9nb3V0UmVzcG9uc2U+',
              RelayState: sessionParticipantLogoutRequestRelayState
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
          expect(xmlhelper.getIssueInstantUTC(sessionParticipantLogoutResponse)).to.equal(frozenTime);
          expect(xmlhelper.getDestination(sessionParticipantLogoutResponse)).to.equal(sessionParticipant1.serviceProviderLogoutURL);
          expect(xmlhelper.getInResponseTo(sessionParticipantLogoutResponse)).to.equal('pfx6fe657e3-1a7f-893e-f690-f7fc5162ea11');
          expect(xmlhelper.getIssuer(sessionParticipantLogoutResponse)).to.equal(samlIdPIssuer);
        });

        it('should response with a Success value', function () {
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
          expect(utils.validateSignature({body : { SAMLResponse: SAMLResponse }}, "LOGOUT_RESPONSE", doc, { signingCert: server.credentials.cert })).to.be.undefined;
        });

        it('should match RelayState with the first request', function(){
          expect(sessionParticipantLogoutResponseRelayState).to.equal('123');
        });

        it('should remove session from sessions array', function () {
          expect(sessions.length).to.equal(0);
        });
      });
    });

    describe('SP Initiated - With Issuer not an URL', function(){
      var samlResponse, action, relayState, logoutResultValue;

      before(function () {
        sessions.splice(0);
        sessions.push({
          serviceProviderId : 'an-issuer',
          nameId: 'foo@example.com',
          nameIdFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
          sessionIndex: '1',
          serviceProviderLogoutURL: 'https://example.com/logout',
          cert: sp1_credentials.cert
        });
      });

      // <samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="samlr-220c705e-c15e-11e6-98a4-ecf4bbce4318" IssueInstant="2016-12-13T18:01:12Z" Version="2.0">
      //   <saml:Issuer>an-issuer</saml:Issuer>
      //   <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">foo@example.com</saml:NameID>
      //   <saml:SessionIndex>3</saml:SessionIndex>
      // </samlp:LogoutRequest>
      before(function (done) {
        request.post({
          followRedirect: false,
          uri: 'http://localhost:5050/logout',
          json: true,
          body: {
            SAMLRequest: 'PHNhbWxwOkxvZ291dFJlcXVlc3QgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgSUQ9InBmeGEwOWQ1MmZiLTZkODAtYjhlYS1jMWE2LTBhMzk5YjYxNjY4MSIgSXNzdWVJbnN0YW50PSIyMDE2LTEyLTEzVDE4OjAxOjEyWiIgVmVyc2lvbj0iMi4wIj4NCiAgICAgICAgPHNhbWw6SXNzdWVyPmFuLWlzc3Vlcjwvc2FtbDpJc3N1ZXI+PGRzOlNpZ25hdHVyZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+DQogIDxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+DQogICAgPGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNyc2Etc2hhMSIvPg0KICA8ZHM6UmVmZXJlbmNlIFVSST0iI3BmeGEwOWQ1MmZiLTZkODAtYjhlYS1jMWE2LTBhMzk5YjYxNjY4MSI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHM6VHJhbnNmb3Jtcz48ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3NoYTEiLz48ZHM6RGlnZXN0VmFsdWU+MGRlQ2ZxbFlhcVkxbGQ2YlVxcmpidHV3SUdVPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT5nTSszUHBwREFGdk1YSnVoVnIvMTRqb1hRWS9wRjIyc1VzMks0VjNCSmpNa21vUU4xL0VVbENrTEc3NXhIdGs5MWd3OE1HNUpySEgyZkZ3V3lyYWxmSXZ5Q281WmQ2aS9SeHdRTlo0bkpncGxWRVRDd09LK3ByNk5QM3hhMHpqWEJld255OWlHZXI2OFQ2dUFVTVQweTZJTUpXbEZGYmhaRW1lWkJ3cE1rVWJjU2VsRHNzSFRvYUR4RFZBdmhOR3pTU1VKd1FyWkYvVjZDOFJkdFRVSUxvZXJzRTVzcktVQVJ5SjZzbWlKck9vVm4reHJOWDBCM0lvMjIyczZSV1d1VU9ibVVsQWRnUzYyb1VzSFV0LzBoSXlvMUJ4c2VMaDd4Nm1kVXY0M1BGTGJqWVZ6eXdTbElIenFEVW5udHV2c0ozTVhKREw4dEJvUFNlbXdPV1g4Z0E9PTwvZHM6U2lnbmF0dXJlVmFsdWU+DQo8ZHM6S2V5SW5mbz48ZHM6WDUwOURhdGEvPjwvZHM6S2V5SW5mbz48L2RzOlNpZ25hdHVyZT4NCiAgICAgICAgPHNhbWw6TmFtZUlEIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6ZW1haWxBZGRyZXNzIj5mb29AZXhhbXBsZS5jb208L3NhbWw6TmFtZUlEPg0KICAgICAgICA8c2FtbDpTZXNzaW9uSW5kZXg+MTwvc2FtbDpTZXNzaW9uSW5kZXg+DQogICAgICA8L3NhbWxwOkxvZ291dFJlcXVlc3Q+',
            RelayState: '123'
          }
        }, function (err, response){
          if(err) return done(err);
          expect(response.statusCode).to.equal(200);
          $ = cheerio.load(response.body);
          var SAMLResponse = $('input[name="SAMLResponse"]').attr('value');
          relayState = $('input[name="RelayState"]').attr('value');
          action = $('form').attr('action');
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

      it('should return RelayState', function () {
        expect(relayState).to.equal('123');
      });

      it('should set action to service provider URL', function(){
        expect(action).to.equal('https://example.com/logout');
      });
    });

    describe('SP initiated - 2 Session Participants - Partial Logout with Error on SP', function () {
      var RelayState;
      // <samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="samlr-220c705e-c15e-11e6-98a4-ecf4bbce4318" IssueInstant="2016-12-13T18:01:12Z" Version="2.0">
      //   <saml:Issuer>https://foobarsupport.zendesk.com</saml:Issuer>
      //   <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">foo@example.com</saml:NameID>
      //   <saml:SessionIndex>1</saml:SessionIndex>
      // </samlp:LogoutRequest>
      before(function (done) {
        sessions.splice(0);
        // Two sessions in the IdP
        sessions.push(sessionParticipant1);
        sessions.push(sessionParticipant2);

        // Logout request sent by SP 1 to IdP
        request.post({
          followRedirect: false,
          uri: 'http://localhost:5050/logout',
          json: true,
          body: {
            SAMLRequest: 'PD94bWwgdmVyc2lvbj0iMS4wIj8+DQo8c2FtbHA6TG9nb3V0UmVxdWVzdCB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0icGZ4NmZlNjU3ZTMtMWE3Zi04OTNlLWY2OTAtZjdmYzUxNjJlYTExIiBJc3N1ZUluc3RhbnQ9IjIwMTYtMTItMTNUMTg6MDE6MTJaIiBWZXJzaW9uPSIyLjAiPg0KICAgICAgICA8c2FtbDpJc3N1ZXI+aHR0cHM6Ly9mb29iYXJzdXBwb3J0LnplbmRlc2suY29tPC9zYW1sOklzc3Vlcj48ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj4NCiAgPGRzOlNpZ25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz4NCiAgICA8ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3JzYS1zaGExIi8+DQogIDxkczpSZWZlcmVuY2UgVVJJPSIjcGZ4NmZlNjU3ZTMtMWE3Zi04OTNlLWY2OTAtZjdmYzUxNjJlYTExIj48ZHM6VHJhbnNmb3Jtcz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PC9kczpUcmFuc2Zvcm1zPjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjc2hhMSIvPjxkczpEaWdlc3RWYWx1ZT55SnpIbmRqL3NuaVJzTG1kcHFSZ0Yvdmp6L0k9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2RzOlNpZ25lZEluZm8+PGRzOlNpZ25hdHVyZVZhbHVlPk56bU42R0RLcHNpMVU4NndaTXNjWjY2aExHNDVhMzhhMGhvaCtpdFdCTWQzNS9RMnF1Y2N2NEJaTGhSbU1xYmFIL3l4VnZ4bWUvWXExR24xbEkrVlpwZkZsYURXQnZTcXUxdWJVemVEbEtVUDdHUmVnakNSTFErSkhxZnQ2aHRDdENQdkttQ0NTaVNEVlZydmcvc0ZLVXBuVDhPWEhkK25ENDBLSVQ4NHQ2OERiM2pTN3g2amx6VDMzYk1Vdm83dVNFUDVnSnFUbG9RMVVWY280WmszUGVxK0tDOWF6TUFkVHVnMWZZRDJXVWtXOEZCd084b1ZBUWpDMGo4VkVyVVpiUUpRS2hhdTMxcjNVcU1VUExNS0NJaFZxZ0tPRVd6MWt1a1NWY2MzdTJjR0owT1FJU093N0xQbkRDSTdPclVMaGU4NEJESTMzR01JMDNXazFMNG5Mdz09PC9kczpTaWduYXR1cmVWYWx1ZT4NCjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YS8+PC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPg0KICAgICAgICA8c2FtbDpOYW1lSUQgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoxLjE6bmFtZWlkLWZvcm1hdDplbWFpbEFkZHJlc3MiPmZvb0BleGFtcGxlLmNvbTwvc2FtbDpOYW1lSUQ+DQogICAgICAgIDxzYW1sOlNlc3Npb25JbmRleD4xPC9zYW1sOlNlc3Npb25JbmRleD4NCiAgICAgIDwvc2FtbHA6TG9nb3V0UmVxdWVzdD4=',
            RelayState: '123'
          }
        }, function (err, response){
          if(err) return done(err);
          expect(response.statusCode).to.equal(200);
          $ = cheerio.load(response.body);
          // IDP Sends LogoutRequest to second IDP
          var SAMLRequest = $('input[name="SAMLRequest"]').attr('value');
          RelayState = $('input[name="RelayState"]').attr('value');
          expect(SAMLRequest).to.be.ok;
          done();
        });
      });

      describe('should send Session Participant LogoutResponse with error to the SAML IdP', function () {
        var SAMLResponse;
        var sessionParticipantLogoutResponse;
        var sessionParticipantLogoutResponseRelayState;

        before(function (done) {
          // <samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_2bba6ea5e677d807f06a" InResponseTo="samlr-220c705e-c15e-11e6-98a4-ecf4bbce4318" Version="2.0" IssueInstant="2016-12-16T13:37:57Z" Destination="http://localhost:5050/logout">
          //     <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://foobarsupport.example.com</saml:Issuer>
          //     <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/>
          //     </samlp:Status>
          // </samlp:LogoutResponse>
          request.post({
            followRedirect: false,
            uri: 'http://localhost:5050/logout',
            json: true,
            body: {
              SAMLResponse: 'PHNhbWxwOkxvZ291dFJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIElEPSJfMmJiYTZlYTVlNjc3ZDgwN2YwNmEiIEluUmVzcG9uc2VUbz0ic2FtbHItMjIwYzcwNWUtYzE1ZS0xMWU2LTk4YTQtZWNmNGJiY2U0MzE4IiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAxNi0xMi0xNlQxMzozNzo1N1oiIERlc3RpbmF0aW9uPSJodHRwOi8vbG9jYWxob3N0OjUwNTAvbG9nb3V0Ij4KICAgIDxzYW1sOklzc3VlciB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj5odHRwczovL2Zvb2JhcnN1cHBvcnQuZXhhbXBsZS5jb208L3NhbWw6SXNzdWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI3JzYS1zaGEyNTYiLz48ZHM6UmVmZXJlbmNlIFVSST0iI18yYmJhNmVhNWU2NzdkODA3ZjA2YSI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHM6VHJhbnNmb3Jtcz48ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjc2hhMjU2Ii8+PGRzOkRpZ2VzdFZhbHVlPko0cEdYY2RlZnZNa3NHYWhsbnFndUFxcmRwanVSMWgvV0t5eUdoV1R6c0U9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2RzOlNpZ25lZEluZm8+PGRzOlNpZ25hdHVyZVZhbHVlPm1XSW1FL3kwY1RLaktTVGc4VGRRcHVoK2pFTkhvRjBBS21KRGxidUM1eHVVWnkvN3c4UEVMMmtQVzlBK3NJNU9lc1B1L0FnRnFUTWlGdFI5WnNpVThIVmFiK285a2M1T2FENzZ4OVdYTit1OFkvdEV5emp3d0tPQmhHRmZYREVKVzZzeTRZN1F0Y2t1Vkw0dVdGTjExcFZ4cHFFTFUyOW5VaFNhR3d2RnpDQUJ2WEd4c3ZkTHJDYndweUloamNyRENjYXRteWhnVFUyNk9aTjY2eHJ4VTg1ZzYzb2RqZE9xWG1YRHFWZ2E0QW81cmd1L2pEQ0ExUzlyOGkyZGlWSWgrV0Y3Y25sN3NuWUVReEpKR3MrWDNCK3RmM091bVJ1dUdsYS9iWEVkZlg5WmFKQVNPZlVVcXg3a25oV0d1c2lnSzQ5Y2l0aUM3aTNRLzMyZkJkMkJqZz09PC9kczpTaWduYXR1cmVWYWx1ZT48ZHM6S2V5SW5mbz48ZHM6WDUwOURhdGEvPjwvZHM6S2V5SW5mbz48L2RzOlNpZ25hdHVyZT4KICAgIDxzYW1scDpTdGF0dXM+PHNhbWxwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6UmVxdWVzdGVyIi8+CiAgICA8L3NhbWxwOlN0YXR1cz4KPC9zYW1scDpMb2dvdXRSZXNwb25zZT4=',
              RelayState: RelayState
            }
          }, function (err, response) {
            if (err) { return done(err); }
            expect(response.statusCode).to.equal(200);
            $ = cheerio.load(response.body);
            SAMLResponse = $('input[name="SAMLResponse"]').attr('value');
            sessionParticipantLogoutResponseRelayState = $('input[name="RelayState"]').attr('value');
            sessionParticipantLogoutResponse = new Buffer(SAMLResponse, 'base64').toString();
            done();
          });
        });

        it('should respond with a partial success value', function () {
          var signedAssertion = /(<samlp:StatusCode.*\/>)/.exec(new Buffer(SAMLResponse, 'base64'))[1];
          var doc = new xmldom.DOMParser().parseFromString(signedAssertion);
          var logoutResultValue = doc.documentElement.getAttribute('Value');
          expect(logoutResultValue).to.equal('urn:oasis:names:tc:SAML:2.0:status:PartialLogout');
        });

        it('should remove session from sessions array', function () {
          expect(sessions.length).to.equal(0);
        });
      });
    });

    describe('SP initiated - 2 Session Participants - Partial Logout with Error on the IdP', function () {
      var SAMLRequest;
      var sessionParticipantLogoutRequest;
      var sessionParticipantLogoutRequestRelayState;

      var sessionParticipant1 = { // Logout Initiator
        serviceProviderId : 'https://foobarsupport.zendesk.com', // Issuer
        nameId: 'foo@example.com',
        nameIdFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
        sessionIndex: '1',
        serviceProviderLogoutURL: 'https://foobarsupport.zendesk.com/logout',
        cert: sp1_credentials.cert // SP1 public Cert
      };

      var sessionParticipant2 = {
        serviceProviderId : 'https://foobarsupport.example.com', // Issuer
        nameId: 'bar@example.com',
        nameIdFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
        sessionIndex: '2',
        serviceProviderLogoutURL: 'https://foobarsupport.example.com/logout',
        cert: sp2_credentials.cert // SP2 public Cert
      };

      // <samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="samlr-220c705e-c15e-11e6-98a4-ecf4bbce4318" IssueInstant="2016-12-13T18:01:12Z" Version="2.0">
      //   <saml:Issuer>https://foobarsupport.zendesk.com</saml:Issuer>
      //   <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">foo@example.com</saml:NameID>
      //   <saml:SessionIndex>1</saml:SessionIndex>
      // </samlp:LogoutRequest>
      before(function (done) {
        returnError = true;

        sessions.splice(0);
        sessions.push(sessionParticipant1);
        sessions.push(sessionParticipant2);

        request.post({
          followRedirect: false,
          uri: 'http://localhost:5050/logout',
          json: true,
          body: {
            SAMLRequest: 'PD94bWwgdmVyc2lvbj0iMS4wIj8+DQo8c2FtbHA6TG9nb3V0UmVxdWVzdCB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0icGZ4NmZlNjU3ZTMtMWE3Zi04OTNlLWY2OTAtZjdmYzUxNjJlYTExIiBJc3N1ZUluc3RhbnQ9IjIwMTYtMTItMTNUMTg6MDE6MTJaIiBWZXJzaW9uPSIyLjAiPg0KICAgICAgICA8c2FtbDpJc3N1ZXI+aHR0cHM6Ly9mb29iYXJzdXBwb3J0LnplbmRlc2suY29tPC9zYW1sOklzc3Vlcj48ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj4NCiAgPGRzOlNpZ25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz4NCiAgICA8ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3JzYS1zaGExIi8+DQogIDxkczpSZWZlcmVuY2UgVVJJPSIjcGZ4NmZlNjU3ZTMtMWE3Zi04OTNlLWY2OTAtZjdmYzUxNjJlYTExIj48ZHM6VHJhbnNmb3Jtcz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PC9kczpUcmFuc2Zvcm1zPjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjc2hhMSIvPjxkczpEaWdlc3RWYWx1ZT55SnpIbmRqL3NuaVJzTG1kcHFSZ0Yvdmp6L0k9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2RzOlNpZ25lZEluZm8+PGRzOlNpZ25hdHVyZVZhbHVlPk56bU42R0RLcHNpMVU4NndaTXNjWjY2aExHNDVhMzhhMGhvaCtpdFdCTWQzNS9RMnF1Y2N2NEJaTGhSbU1xYmFIL3l4VnZ4bWUvWXExR24xbEkrVlpwZkZsYURXQnZTcXUxdWJVemVEbEtVUDdHUmVnakNSTFErSkhxZnQ2aHRDdENQdkttQ0NTaVNEVlZydmcvc0ZLVXBuVDhPWEhkK25ENDBLSVQ4NHQ2OERiM2pTN3g2amx6VDMzYk1Vdm83dVNFUDVnSnFUbG9RMVVWY280WmszUGVxK0tDOWF6TUFkVHVnMWZZRDJXVWtXOEZCd084b1ZBUWpDMGo4VkVyVVpiUUpRS2hhdTMxcjNVcU1VUExNS0NJaFZxZ0tPRVd6MWt1a1NWY2MzdTJjR0owT1FJU093N0xQbkRDSTdPclVMaGU4NEJESTMzR01JMDNXazFMNG5Mdz09PC9kczpTaWduYXR1cmVWYWx1ZT4NCjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YS8+PC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPg0KICAgICAgICA8c2FtbDpOYW1lSUQgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoxLjE6bmFtZWlkLWZvcm1hdDplbWFpbEFkZHJlc3MiPmZvb0BleGFtcGxlLmNvbTwvc2FtbDpOYW1lSUQ+DQogICAgICAgIDxzYW1sOlNlc3Npb25JbmRleD4xPC9zYW1sOlNlc3Npb25JbmRleD4NCiAgICAgIDwvc2FtbHA6TG9nb3V0UmVxdWVzdD4=',
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

      describe('should send Session Participant LogoutResponse to the SAML IdP', function () {
        var SAMLResponse, RelayState;

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
            followRedirect: false,
            uri: 'http://localhost:5050/logout',
            json: true,
            body: {
              SAMLResponse: 'PHNhbWxwOkxvZ291dFJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIElEPSJfMmJiYTZlYTVlNjc3ZDgwN2YwNmEiIEluUmVzcG9uc2VUbz0ic2FtbHItMjIwYzcwNWUtYzE1ZS0xMWU2LTk4YTQtZWNmNGJiY2U0MzE4IiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAxNi0xMi0xNlQxMzozNzo1N1oiIERlc3RpbmF0aW9uPSJodHRwOi8vbG9jYWxob3N0OjUwNTAvbG9nb3V0Ij4KICAgIDxzYW1sOklzc3VlciB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj5odHRwczovL2Zvb2JhcnN1cHBvcnQuZXhhbXBsZS5jb208L3NhbWw6SXNzdWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI3JzYS1zaGEyNTYiLz48ZHM6UmVmZXJlbmNlIFVSST0iI18yYmJhNmVhNWU2NzdkODA3ZjA2YSI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHM6VHJhbnNmb3Jtcz48ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjc2hhMjU2Ii8+PGRzOkRpZ2VzdFZhbHVlPkxXUmUrbGNNR0VRYTlPYjlsc0hpUk5Ob29pUDgyM2JwVFA2OFVXMUdRR0U9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2RzOlNpZ25lZEluZm8+PGRzOlNpZ25hdHVyZVZhbHVlPkJoaDlMZmt3bnRaL2lBTzJvNDliWXRWZG02UTlRbjNQbDZ0Ulh2a0pKMFU2RWtWOHFaMzB6Z2JnZ21wK3c0a1U5TU1GL1d3ZVBzMDZ0VXd6Ny83bTU5VitYaVl0Um5BYk5QRUtvU29vT2FKZE9yMzc5YlU0ano4S1dZVzJWY1RnVUw2dndTaGhzczVIaFlIZ3ZxbHpnVU9iN1ZIejJuUnhLM1RvSWl3VVF2RWs1WFNQeXJUejU2TG9neTMxczgyODNBR2tBcm5jdTBPYzh5ckN6bTlCOFN1aXR4YVVORW5yV2lwcTFOTTQ4TE5LQUhCNFRlOHFIYm5pTW51VDRRc2VFVVhJTk9QVzJzWDBlcnFtOEI2c3RsTFdwaWwva2hYbGliZk5lTjE4MWVUbW5QUDlDR2t3N0ZuTm56UzNQUDlQYTJ5bU9rRG9lSkRSQy9GQ294bVFXdz09PC9kczpTaWduYXR1cmVWYWx1ZT48ZHM6S2V5SW5mbz48ZHM6WDUwOURhdGEvPjwvZHM6S2V5SW5mbz48L2RzOlNpZ25hdHVyZT4KICAgIDxzYW1scDpTdGF0dXM+PHNhbWxwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIvPgogICAgPC9zYW1scDpTdGF0dXM+Cjwvc2FtbHA6TG9nb3V0UmVzcG9uc2U+',
              RelayState: sessionParticipantLogoutRequestRelayState
            }
          }, function (err, response) {
            if (err) { return done(err); }
            expect(response.statusCode).to.equal(200);
            $ = cheerio.load(response.body);
            SAMLResponse = $('input[name="SAMLResponse"]').attr('value');
            RelayState = $('input[name="RelayState"]').attr('value');
            done();
          });
        });

        it('should respond with a Success value', function () {
          var signedAssertion = /(<samlp:StatusCode.*\/>)/.exec(new Buffer(SAMLResponse, 'base64'))[1];
          var doc = new xmldom.DOMParser().parseFromString(signedAssertion);
          var logoutResultValue = doc.documentElement.getAttribute('Value');
          expect(logoutResultValue).to.equal('urn:oasis:names:tc:SAML:2.0:status:PartialLogout');
        });

        it('should match RelayState with the first request', function () {
          expect(RelayState).to.equal('123');
        });
      });
    });

    describe('SP initiated - Invalid signature', function () {
      var response;

      before(function () {
        sessions.splice(0);
        sessions.push({
          serviceProviderId : 'https://foobarsupport.zendesk.com',
          nameId: 'foo@example.com',
          sessionIndex: '1',
          serviceProviderLogoutURL: 'https://example.com/logout',
          cert: sp1_credentials.cert
        });
      });

      before(function (done) {
        request.post({
          jar: request.jar(),
          followRedirect: false,
          uri: 'http://localhost:5050/logout',
          json: true,
          body: {
            SAMLRequest: 'PHNhbWxwOkxvZ291dFJlcXVlc3QgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgSUQ9InNhbWxyLTIyMGM3MDVlLWMxNWUtMTFlNi05OGE0LWVjZjRiYmNlNDMxOCIgSXNzdWVJbnN0YW50PSIyMDE2LTEyLTEzVDE4OjAxOjEyWiIgVmVyc2lvbj0iMi4wIj4KICA8c2FtbDpJc3N1ZXI+aHR0cHM6Ly9mb29iYXJzdXBwb3J0LnplbmRlc2suY29tPC9zYW1sOklzc3Vlcj48ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj48ZHM6U2lnbmVkSW5mbz48ZHM6Q2Fub25pY2FsaXphdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGRzaWctbW9yZSNyc2Etc2hhMjU2Ii8+PGRzOlJlZmVyZW5jZSBVUkk9IiNzYW1sci0yMjBjNzA1ZS1jMTVlLTExZTYtOThhNC1lY2Y0YmJjZTQzMTgiPjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiIvPjxkczpEaWdlc3RWYWx1ZT5YRENVcm5mbENKUTJ3bVV5bmFWaDRDRnZNOUx2MHdUTXBUSUkxbEVtTi9FPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT5hc2lkanBhc2pkcGFzam5kb3VidnVvamV3cHJqd2Vwcmo8L2RzOlNpZ25hdHVyZVZhbHVlPjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YS8+PC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPgogIDxzYW1sOk5hbWVJRCBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjEuMTpuYW1laWQtZm9ybWF0OmVtYWlsQWRkcmVzcyI+Zm9vQGV4YW1wbGUuY29tPC9zYW1sOk5hbWVJRD4KICA8c2FtbHA6U2Vzc2lvbkluZGV4PjE8L3NhbWxwOlNlc3Npb25JbmRleD4KPC9zYW1scDpMb2dvdXRSZXF1ZXN0Pg==',
            RelayState: '123'
          }
        }, function (err, res){
          if(err) return done(err);
          response = res;

          done();
        });
      });

      it('should return invalid signature error', function () {
        expect(response.statusCode).to.equal(400);
        // TODO: Improve this error message
        expect(response.body).to.equal('Signature check errors: invalid signature: the signature value asidjpasjdpasjndoubvuojewprjweprj is incorrect');
      });
    });

    describe('SP initiated - Session Index does not match an active session', function(){
      var response;

      before(function () {
        sessions.splice(0);
        sessions.push({
          serviceProviderId : 'https://foobarsupport.zendesk.com',
          nameId: 'foo@example.com',
          sessionIndex: '1',
          serviceProviderLogoutURL: 'https://example.com/logout',
          cert: sp1_credentials.cert
        });
      });

      before(function (done) {
        request.post({
          jar: request.jar(),
          followRedirect: false,
          uri: 'http://localhost:5050/logout',
          json: true,
          body: {
            // Different sessionIndex
            SAMLRequest: 'PHNhbWxwOkxvZ291dFJlcXVlc3QgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgSUQ9InNhbWxyLTIyMGM3MDVlLWMxNWUtMTFlNi05OGE0LWVjZjRiYmNlNDMxOCIgSXNzdWVJbnN0YW50PSIyMDE2LTEyLTEzVDE4OjAxOjEyWiIgVmVyc2lvbj0iMi4wIj4KICA8c2FtbDpJc3N1ZXI+aHR0cHM6Ly9mb29iYXJzdXBwb3J0LnplbmRlc2suY29tPC9zYW1sOklzc3Vlcj48ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj48ZHM6U2lnbmVkSW5mbz48ZHM6Q2Fub25pY2FsaXphdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGRzaWctbW9yZSNyc2Etc2hhMjU2Ii8+PGRzOlJlZmVyZW5jZSBVUkk9IiNzYW1sci0yMjBjNzA1ZS1jMTVlLTExZTYtOThhNC1lY2Y0YmJjZTQzMTgiPjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiIvPjxkczpEaWdlc3RWYWx1ZT5tV1RvQUJuVExDd0xJOEFFOW1RYnFTZ3NCVnNsOXNpWG9sMG9yVXVUa0dBPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT5hc2lkanBhc2pkcGFzam5kb3VidnVvamV3cHJqd2Vwcmo8L2RzOlNpZ25hdHVyZVZhbHVlPjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YS8+PC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPgogIDxzYW1sOk5hbWVJRCBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjEuMTpuYW1laWQtZm9ybWF0OmVtYWlsQWRkcmVzcyI+Zm9vQGV4YW1wbGUuY29tPC9zYW1sOk5hbWVJRD4KICA8c2FtbDpTZXNzaW9uSW5kZXg+MTIzPC9zYW1sOlNlc3Npb25JbmRleD4KPC9zYW1scDpMb2dvdXRSZXF1ZXN0Pg==',
            RelayState: '123'
          }
        }, function (err, res){
          if(err) return done(err);
          response = res;

          done();
        });
      });

      it('should return invalid session participant', function () {
        expect(response.statusCode).to.equal(400);
        expect(response.body).to.equal('Invalid Session Participant');
      });
    });

    describe('SP initiated - NameID does not match an active session', function(){
      var response;

      before(function () {
        sessions.splice(0);
        sessions.push({
          serviceProviderId : 'https://foobarsupport.zendesk.com',
          nameId: 'foo@example.com',
          sessionIndex: '1',
          serviceProviderLogoutURL: 'https://example.com/logout',
          cert: sp1_credentials.cert
        });
      });

      before(function (done) {
        request.post({
          jar: request.jar(),
          followRedirect: false,
          uri: 'http://localhost:5050/logout',
          json: true,
          body: {
            // Different nameID
            SAMLRequest: 'PHNhbWxwOkxvZ291dFJlcXVlc3QgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgSUQ9InNhbWxyLTIyMGM3MDVlLWMxNWUtMTFlNi05OGE0LWVjZjRiYmNlNDMxOCIgSXNzdWVJbnN0YW50PSIyMDE2LTEyLTEzVDE4OjAxOjEyWiIgVmVyc2lvbj0iMi4wIj4KICA8c2FtbDpJc3N1ZXI+aHR0cHM6Ly9mb29iYXJzdXBwb3J0LnplbmRlc2suY29tPC9zYW1sOklzc3Vlcj48ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj48ZHM6U2lnbmVkSW5mbz48ZHM6Q2Fub25pY2FsaXphdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGRzaWctbW9yZSNyc2Etc2hhMjU2Ii8+PGRzOlJlZmVyZW5jZSBVUkk9IiNzYW1sci0yMjBjNzA1ZS1jMTVlLTExZTYtOThhNC1lY2Y0YmJjZTQzMTgiPjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiIvPjxkczpEaWdlc3RWYWx1ZT5tV1RvQUJuVExDd0xJOEFFOW1RYnFTZ3NCVnNsOXNpWG9sMG9yVXVUa0dBPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT5hc2lkanBhc2pkcGFzam5kb3VidnVvamV3cHJqd2Vwcmo8L2RzOlNpZ25hdHVyZVZhbHVlPjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YS8+PC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPgogIDxzYW1sOk5hbWVJRCBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjEuMTpuYW1laWQtZm9ybWF0OmVtYWlsQWRkcmVzcyI+YmFyQGV4YW1wbGUuY29tPC9zYW1sOk5hbWVJRD4KICA8c2FtbDpTZXNzaW9uSW5kZXg+MTwvc2FtbDpTZXNzaW9uSW5kZXg+Cjwvc2FtbHA6TG9nb3V0UmVxdWVzdD4=',
            RelayState: '123'
          }
        }, function (err, res){
          if(err) return done(err);
          response = res;

          done();
        });
      });

      it('should return invalid session participant', function () {
        expect(response.statusCode).to.equal(400);
        expect(response.body).to.equal('Invalid Session Participant');
      });
    });

    describe('SP initiated - 1 Session Participant with Redirect binding', function () {
      var logoutResponse;

      before(function () {
        prepareOneParticipant(BINDINGS.HTTP_REDIRECT);
      });

      before(function (done) {
        logoutPostSPInitiated(function(err, response){
          if (err) return done(err);
          logoutResponse = response;
          done();
        });
      });

      it('Should return Redirect request', function () {
        assertRedirectResponse(logoutResponse);
      });
    });

    describe('SP initiated - 2 Session Participants with Redirect binding', function() {
      var logoutResponse;

      before(function () {
        prepareTwoParticipants(BINDINGS.HTTP_REDIRECT);
      });

      before(function (done) {
        logoutPostSPInitiated(function(err, response){
          if (err) return done(err);
          logoutResponse = response;
          done();
        });
      });

      it('Should return Redirect request', function () {
        assertRedirectResponse(logoutResponse);
      });
    });
  });
});

describe('samlp logout with Session Participants - Session Provider', function () {
  var sessions = [], returnError;
  var samlIdPIssuer = 'urn:fixture-test';
  var configuredDestination = 'default-destination-url';

  before(function (done) {
    server.start( {
      audience: 'https://auth0-dev-ed.my.salesforce.com',
      issuer: samlIdPIssuer,
      clearIdPSession: function(cb){
        if (returnError){
          return cb(new Error('There was an error cleaning session'));
        }
        cb();
      },
      destination: configuredDestination,
      sessionParticipants: new SPs(sessions)
    },done);
  });

  after(function (done) {
    server.close(done);
  });

  describe('SP initiated - Should reply back when configured with default destination and there is no session', function(){
    var logoutResultValue, relayState, samlResponse, signedAssertion, $, destination;

    before(function () {
      // No sessions
      sessions = [];
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
        followRedirect: false,
        uri: 'http://localhost:5050/logout',
        json: true,
        body: {
          SAMLRequest: 'PD94bWwgdmVyc2lvbj0iMS4wIj8+DQo8c2FtbHA6TG9nb3V0UmVxdWVzdCB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0icGZ4NmZlNjU3ZTMtMWE3Zi04OTNlLWY2OTAtZjdmYzUxNjJlYTExIiBJc3N1ZUluc3RhbnQ9IjIwMTYtMTItMTNUMTg6MDE6MTJaIiBWZXJzaW9uPSIyLjAiPg0KICAgICAgICA8c2FtbDpJc3N1ZXI+aHR0cHM6Ly9mb29iYXJzdXBwb3J0LnplbmRlc2suY29tPC9zYW1sOklzc3Vlcj48ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj4NCiAgPGRzOlNpZ25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz4NCiAgICA8ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3JzYS1zaGExIi8+DQogIDxkczpSZWZlcmVuY2UgVVJJPSIjcGZ4NmZlNjU3ZTMtMWE3Zi04OTNlLWY2OTAtZjdmYzUxNjJlYTExIj48ZHM6VHJhbnNmb3Jtcz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PC9kczpUcmFuc2Zvcm1zPjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjc2hhMSIvPjxkczpEaWdlc3RWYWx1ZT55SnpIbmRqL3NuaVJzTG1kcHFSZ0Yvdmp6L0k9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2RzOlNpZ25lZEluZm8+PGRzOlNpZ25hdHVyZVZhbHVlPk56bU42R0RLcHNpMVU4NndaTXNjWjY2aExHNDVhMzhhMGhvaCtpdFdCTWQzNS9RMnF1Y2N2NEJaTGhSbU1xYmFIL3l4VnZ4bWUvWXExR24xbEkrVlpwZkZsYURXQnZTcXUxdWJVemVEbEtVUDdHUmVnakNSTFErSkhxZnQ2aHRDdENQdkttQ0NTaVNEVlZydmcvc0ZLVXBuVDhPWEhkK25ENDBLSVQ4NHQ2OERiM2pTN3g2amx6VDMzYk1Vdm83dVNFUDVnSnFUbG9RMVVWY280WmszUGVxK0tDOWF6TUFkVHVnMWZZRDJXVWtXOEZCd084b1ZBUWpDMGo4VkVyVVpiUUpRS2hhdTMxcjNVcU1VUExNS0NJaFZxZ0tPRVd6MWt1a1NWY2MzdTJjR0owT1FJU093N0xQbkRDSTdPclVMaGU4NEJESTMzR01JMDNXazFMNG5Mdz09PC9kczpTaWduYXR1cmVWYWx1ZT4NCjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YS8+PC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPg0KICAgICAgICA8c2FtbDpOYW1lSUQgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoxLjE6bmFtZWlkLWZvcm1hdDplbWFpbEFkZHJlc3MiPmZvb0BleGFtcGxlLmNvbTwvc2FtbDpOYW1lSUQ+DQogICAgICAgIDxzYW1sOlNlc3Npb25JbmRleD4xPC9zYW1sOlNlc3Npb25JbmRleD4NCiAgICAgIDwvc2FtbHA6TG9nb3V0UmVxdWVzdD4=',
          RelayState: '123'
        }
      }, function (err, response){
        if (err) { return done(err); }

        expect(response.statusCode).to.equal(200);
        $ = cheerio.load(response.body);
        var SAMLResponse = $('input[name="SAMLResponse"]').attr('value');
        destination = $('form').attr('action');
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

    it('should post to destination URL', function () {
      expect(destination).to.equal(configuredDestination);
    });
  });
});
