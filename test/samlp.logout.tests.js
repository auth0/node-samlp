var expect = require('chai').expect;
var server = require('./fixture/server');
var request = require('request');
var cheerio = require('cheerio');
var xmldom = require('xmldom');
var zlib = require('zlib');

describe('samlp logout', function () {
  before(function (done) {
    server.start( { 
      audience: 'https://auth0-dev-ed.my.salesforce.com'
    },done);
  });

  after(function (done) {
    server.close(done);
  });

  var body, $, signedAssertion, logoutResultValue;

  beforeEach(function (done) {
    // <?xml version="1.0" encoding="UTF-8"?>
    // <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" AssertionConsumerServiceURL="https://login.salesforce.com"
    //   Destination="https://contoso.auth0.com/saml" ID="_2N5GGp2nmITCFbcyGSKjaQ3ai6Kx9cAwDhBGX1gAJyvCrlJvoEQdjEgTsfajgM9m7j.w.I9Fz1ddVjZ9lKZChcsptp9kxkCuqcwbeNe.lJyVQpB8iSa4awFYsj9A5r7REb5JpHH72B6feguHFFPE8Mak3u4hSEKl9_8moiXLdA57WVhzwa8XYxn4mDshSp3Xb0PEZKODHMtxlVXaycGYuMgC20GpfCA"
    //   IssueInstant="2013-04-28T22:43:42.386Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0">
    //   <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://auth0-dev-ed.my.salesforce.com</saml:Issuer>
    // </samlp:AuthnRequest>
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

  describe('SP initiated - Redirect binding (GET)', function () {
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
  });

  describe('SP initiated - HTTP Post Binding', function(){
    var samlResponse, relayState;
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

    it('should return RelayState', function () {
      expect(relayState).to.equal('123');
    });
  });

  describe('errors', function(){
    var response;    

    describe('HTTP-POST - Invalid signature', function(){
      before(function (done) {
        request.post({
          jar: request.jar(),
          followRedirect: false,
          uri: 'http://localhost:5050/logout',
          json: true,
          body: {
            SAMLRequest: 'PHNhbWxwOkxvZ291dFJlcXVlc3QgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgSUQ9InNhbWxyLTIyMGM3MDVlLWMxNWUtMTFlNi05OGE0LWVjZjRiYmNlNDMxOCIgSXNzdWVJbnN0YW50PSIyMDE2LTEyLTEzVDE4OjAxOjEyWiIgVmVyc2lvbj0iMi4wIj4KICA8c2FtbDpJc3N1ZXI+aHR0cHM6Ly9mb29iYXJzdXBwb3J0LnplbmRlc2suY29tPC9zYW1sOklzc3Vlcj48ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj48ZHM6U2lnbmVkSW5mbz48ZHM6Q2Fub25pY2FsaXphdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGRzaWctbW9yZSNyc2Etc2hhMjU2Ii8+PGRzOlJlZmVyZW5jZSBVUkk9IiNzYW1sci0yMjBjNzA1ZS1jMTVlLTExZTYtOThhNC1lY2Y0YmJjZTQzMTgiPjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiIvPjxkczpEaWdlc3RWYWx1ZT5tV1RvQUJuVExDd0xJOEFFOW1RYnFTZ3NCVnNsOXNpWG9sMG9yVXVUa0dBPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT5hc2lkanBhc2pkcGFzam5kb3VidnVvamV3cHJqd2Vwcmo8L2RzOlNpZ25hdHVyZVZhbHVlPjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YS8+PC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPgogIDxzYW1sOk5hbWVJRCBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjEuMTpuYW1laWQtZm9ybWF0OmVtYWlsQWRkcmVzcyI+Zm9vQGV4YW1wbGUuY29tPC9zYW1sOk5hbWVJRD4KICA8c2FtbDpTZXNzaW9uSW5kZXg+MTwvc2FtbDpTZXNzaW9uSW5kZXg+Cjwvc2FtbHA6TG9nb3V0UmVxdWVzdD4=',
            RelayState: '123'
          }
        }, function (err, res){
          if(err) return done(err);
          response = res;

          done();
        });
      });

      it('should return invalid signture error', function(){
        expect(response.statusCode).to.equal(400);
        // TODO: Improve this error message
        expect(response.body).to.equal('Signature check errors: invalid signature: the signature value asidjpasjdpasjndoubvuojewprjweprj is incorrect');
      });
    });

    describe('HTTP-Post - Invalid signature', function(){
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
          uri: 'http://localhost:5050/logout?SAMLRequest=fZFBS8NAEIXvhf6HsPdNM2mtdWiDhSIEqgdbPHjbbqYazO7GnQ0Uf73bVDAKetnDm%2B%2FNm8cuWZmmxa17cV14pPeOOCQn01jGfrISnbfoFNeMVhliDBp36%2Fst5mmGrXfBadeIgeV%2Fh2ImH2pnRVJuVuJs8DLPM32dXZHUEB8AmsubhZpJ0sfZ4aBpNoVF5Jk7Ki0HZcNK5BnMJeQSpntYYAYI%2BbNInshzXB7HaSaK8ShJlucI7L2%2BeA2hZZxMjs4dlOeubZ0P6QfZivgt1c4sJ0P82%2F8Qi5Sb5M55o8LfDSGFXqkreexRJKPqZl1VnphFEXNv6aRM29Ag7bJ8kLaLcGxRxrNOBXxRP8Tx6KL%2B%2BrniEw%3D%3D&Signature=asidjpasjdpasjndoubvuojewprjweprj&RelayState=123&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1'
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

  });

  // IdP Initiated with no Session Participants should not happen
  // At least we should have 1 session participant. Still should not return an error
  describe('IdP initiated', function () {
    var body;
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

  describe('SP initiated - with default configuration', function(){
    // SAMLRequest: base64 encoded + deflated + URLEncoded
    // Signature: URLEncoded
    // SigAlg: URLEncoded

    // <samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="samlr-220c705e-c15e-11e6-98a4-ecf4bbce4318" IssueInstant="2016-12-13T18:01:12Z" Version="2.0">
    //   <saml:Issuer>https://foobarsupport.zendesk.com</saml:Issuer>
    //   <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">foo@example.com</saml:NameID>
    //   <saml:SessionIndex>1</saml:SessionIndex>
    // </samlp:LogoutRequest>
    before(function (done) {
      server.options.protocolBinding = '';
      
      request.get({
        jar: request.jar(),
        followRedirect: false,
        uri: 'http://localhost:5050/logout?SAMLRequest=fZFBS8NAEIXvhf6HsPdNM2mtdWiDhSIEqgdbPHjbbqYazO7GnQ0Uf73bVDAKetnDm%2B%2FNm8cuWZmmxa17cV14pPeOOCQn01jGfrISnbfoFNeMVhliDBp36%2Fst5mmGrXfBadeIgeV%2Fh2ImH2pnRVJuVuJs8DLPM32dXZHUEB8AmsubhZpJ0sfZ4aBpNoVF5Jk7Ki0HZcNK5BnMJeQSpntYYAYI%2BbNInshzXB7HaSaK8ShJlucI7L2%2BeA2hZZxMjs4dlOeubZ0P6QfZivgt1c4sJ0P82%2F8Qi5Sb5M55o8LfDSGFXqkreexRJKPqZl1VnphFEXNv6aRM29Ag7bJ8kLaLcGxRxrNOBXxRP8Tx6KL%2B%2BrniEw%3D%3D&Signature=KH%2FBMO0DJyS2Ffy%2B6Rnb11pAF37Y%2Beua7RHcFhVrwgxJEqsx59vTelrfPt771JPfr7%2BoG1uYwwO3Algs59yTeqmU35x18Bf2e0yWugqEF7wxHETCjrwbCK1YjYg0ilwCojk%2FBTTv2Rs%2BY7RB21Ou1GShT1uXv8WItj7E2qnr%2B6kHY5XJWTJukZa9Vnkx%2FiisA7n6UfnnGcWMdltYeOvyHvOFMVG43dDxBms9WKMKdxn6NJ7i2V1v7nXj1DoXD4PDH5B6aevkA49c6mpzozyXKLeXLys%2FvPNNT4cC1jmWvuen5pe%2FE1WfgcZcZvj2GGaxs36fdH%2FHsIcyDvE%2Bj7ngYw%3D%3D&RelayState=123&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1'
      }, function (err, response){
        if(err) return done(err);
        expect(response.statusCode).to.equal(200);
        $ = cheerio.load(response.body);
        var SAMLResponse = $('input[name="SAMLResponse"]').attr('value');
        var samlResponse = new Buffer(SAMLResponse, 'base64');
        signedAssertion = /(<samlp:StatusCode.*\/>)/.exec(samlResponse)[1];
        var doc = new xmldom.DOMParser().parseFromString(signedAssertion);
        logoutResultValue = doc.documentElement.getAttribute('Value');

        done();
      });
    });

    it('should respond with a Success value', function () {
      expect(logoutResultValue).to.equal('urn:oasis:names:tc:SAML:2.0:status:Success');
    });
  });
});