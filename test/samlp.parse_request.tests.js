'use strict'

var expect = require('chai').expect;
var samlp = require('../lib')
var encoder = require('../lib/encoders');
var fs = require('fs')
var path = require('path')
var zlib = require('zlib');

var requestWithAuthnContextClassRef = `<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="pfx9702ffd6-91a0-24bd-17f6-c66a3ac24f70" AssertionConsumerServiceURL="https://acs" Destination="https://destination" IssueInstant="2013-04-28T22:43:42.386Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><saml:Subject xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:NameID>test@samlreq.com</saml:NameID></saml:Subject><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://sp</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfx9702ffd6-91a0-24bd-17f6-c66a3ac24f70"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>GhzsHhoK8QpTW5Q54Ab9zstSenc=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>BJheKXguoWu+UuLXMU7Lxctv2h4wZnSrX1A15USop5kndsUMOMp0Zs5qkUtMfjuJnbpIZkfboz2Rca61E805k59zOW6IzNFnXfXf38YJ1CJ7RDoFYdF/PR4QSzCIfK/X4R/K+IWi9Janhr472kJLV4eHi+FH3hIVzZFT33xt6tfAkmPmxdjaVuDBEg+ytIDY6usthAKcxOtlJiCqmiGRFM/5wvPnK1X0roHsMnUPCdW2uOhCB9XqqaWWz/4AesxCA3v3RXhT5CvI9bs/J9zyjAoiCq0KDHY6nBykGqO8GCL6gvLJuM5tN790m1MhRxvdRTwCmV6OO9cMJ2kk8Y94pg==</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDtTCCAp2gAwIBAgIJAMKR/NsyfcazMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTIxMTEyMjM0MzQxWhcNMTYxMjIxMjM0MzQxWjBFMQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvtH4wKLYlIXZlfYQFJtXZVC3fD8XMarzwvb/fHUyJ6NvNStN+H7GHp3/QhZbSaRyqK5hu5xXtFLgnI0QG8oE1NlXbczjH45LeHWhPIdc2uHSpzXic78kOugMY1vng4J10PF6+T2FNaiv0iXeIQq9xbwwPYpflViQyJnzGCIZ7VGan6GbRKzyTKcB58yx24pJq+CviLXEY52TIW1l5imcjGvLtlCp1za9qBZa4XGoVqHi1kRXkdDSHty6lZWj3KxoRvTbiaBCH+75U7rifS6fR9lqjWE57bCGoz7+BBu9YmPKtI1KkyHFqWpxaJc/AKf9xgg+UumeqVcirUmAsHJrMwIDAQABo4GnMIGkMB0GA1UdDgQWBBTs83nkLtoXFlmBUts3EIxcVvkvcjB1BgNVHSMEbjBsgBTs83nkLtoXFlmBUts3EIxcVvkvcqFJpEcwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZIIJAMKR/NsyfcazMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBABw7w/5k4d5dVDgd/OOOmXdaaCIKvt7d3ntlv1SSvAoKT8d8lt97Dm5RrmefBI13I2yivZg5bfTge4+vAV6VdLFdWeFp1b/FOZkYUv6A8o5HW0OWQYVX26zIqBcG2Qrm3reiSl5BLvpj1WSpCsYvs5kaO4vFpMak/ICgdZD+rxwxf8Vb/6fntKywWSLgwKH3mJ+Z0kRlpq1g1oieiOm1/gpZ35s0YuorXZba9ptfLCYSggg/qc3d3d0tbHplKYkwFm7f5ORGHDSD5SJm+gI7RPE+4bO8q79RPAfbG1UGuJ0b/oigagciHhJp851SQRYf3JuNSc17BnK2L5IEtzjqr+Q=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/><samlp:RequestedAuthnContext Comparison="exact"><samlp:AuthnContextClassRef>http://schemas.openid.net/pape/policies/2007/06/multi-factor</samlp:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>`;

var requestWithoutAuthnContextClassRef = `<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="pfxa4ada2aa-21ed-2788-7f49-e708fdaebc88" AssertionConsumerServiceURL="https://acs" Destination="https://destination" IssueInstant="2013-04-28T22:43:42.386Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0">
<saml:Subject xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
<saml:NameID>test@samlreq.com</saml:NameID>
</saml:Subject>
<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://sp</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfxa4ada2aa-21ed-2788-7f49-e708fdaebc88"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>UZB6cYGRYoUa2Mt+LqU+D+7qZlI=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>n7Icnw3cwlZjfhNaXDTAoFycIZew8i0dHspZVKmxk9KxRapRwJ0InFkJT4wLTs+58mlPob7m0bEHT9ph1QHkA5tzDa1dja2nCtIvEgL3ajsKpW2LEzbCVFmoCEXSBZ19LePjLzmXHI2TptEbuNoIIoWWRVuWjcuz0QQGKhbukSC8KQI/6UeVGk3CQWCYxnkwl7jnGmDkawoiyTAWssTvVq90tdzGhuRBSXwat8ncfYwAxbP+Sip3Qqyh5gkqP4AnfKp1jG7LTHxY+HQ+XmntIDESHVj+VYrWfpKI2L/sZDKgSEzjOGhzwBWRIoC9yK4SYDUmru0LO1i2dO52MqfutQ==</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDtTCCAp2gAwIBAgIJAMKR/NsyfcazMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTIxMTEyMjM0MzQxWhcNMTYxMjIxMjM0MzQxWjBFMQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvtH4wKLYlIXZlfYQFJtXZVC3fD8XMarzwvb/fHUyJ6NvNStN+H7GHp3/QhZbSaRyqK5hu5xXtFLgnI0QG8oE1NlXbczjH45LeHWhPIdc2uHSpzXic78kOugMY1vng4J10PF6+T2FNaiv0iXeIQq9xbwwPYpflViQyJnzGCIZ7VGan6GbRKzyTKcB58yx24pJq+CviLXEY52TIW1l5imcjGvLtlCp1za9qBZa4XGoVqHi1kRXkdDSHty6lZWj3KxoRvTbiaBCH+75U7rifS6fR9lqjWE57bCGoz7+BBu9YmPKtI1KkyHFqWpxaJc/AKf9xgg+UumeqVcirUmAsHJrMwIDAQABo4GnMIGkMB0GA1UdDgQWBBTs83nkLtoXFlmBUts3EIxcVvkvcjB1BgNVHSMEbjBsgBTs83nkLtoXFlmBUts3EIxcVvkvcqFJpEcwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZIIJAMKR/NsyfcazMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBABw7w/5k4d5dVDgd/OOOmXdaaCIKvt7d3ntlv1SSvAoKT8d8lt97Dm5RrmefBI13I2yivZg5bfTge4+vAV6VdLFdWeFp1b/FOZkYUv6A8o5HW0OWQYVX26zIqBcG2Qrm3reiSl5BLvpj1WSpCsYvs5kaO4vFpMak/ICgdZD+rxwxf8Vb/6fntKywWSLgwKH3mJ+Z0kRlpq1g1oieiOm1/gpZ35s0YuorXZba9ptfLCYSggg/qc3d3d0tbHplKYkwFm7f5ORGHDSD5SJm+gI7RPE+4bO8q79RPAfbG1UGuJ0b/oigagciHhJp851SQRYf3JuNSc17BnK2L5IEtzjqr+Q=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
</samlp:AuthnRequest>`;

describe('samlp parse response', function () {
  var cert;

  before(function () {
    cert = fs.readFileSync(path.join(__dirname, 'fixture/samlp.test-cert.pem'));
  });

  describe('SAMLRequest on querystring', function () {
    let parseResult;

    describe('when request has authnContextClassRef', function () {
      it('should return a valid response', function (done) {
        samlp.parseRequest({
          query: {
            SAMLRequest: new Buffer(requestWithAuthnContextClassRef).toString('base64'),
            RelayState: '123'
          }
        }, {
          signingCert: cert,
          thumbprints: [encoder.thumbprint(cert)],
          relayState: '123'
        }, function (err, result) {
          expect(err).not.to.exist;
          expect(result).to.eql({
            issuer: 'http://sp',
            subject: 'test@samlreq.com',
            assertionConsumerServiceURL: 'https://acs',
            destination: 'https://destination',
            id: 'pfx9702ffd6-91a0-24bd-17f6-c66a3ac24f70',
            requestedAuthnContext: {
              authnContextClassRef: 'http://schemas.openid.net/pape/policies/2007/06/multi-factor'
            }
          });

          done();
        })
      });
    });

    describe('when request does not have authnContextClassRef', function () {
      it('should return a valid response', function (done) {
        samlp.parseRequest({
          query: {
            SAMLRequest: new Buffer(requestWithoutAuthnContextClassRef).toString('base64'),
            RelayState: '123'
          }
        }, {
          signingCert: cert,
          thumbprints: [encoder.thumbprint(cert)],
          relayState: '123'
        }, function (err, result) {
          if (err) {
            done(err);
            return;
          }

          expect(err).not.to.exist;
          expect(result).to.eql({
            issuer: 'http://sp',
            subject: 'test@samlreq.com',
            assertionConsumerServiceURL: 'https://acs',
            destination: 'https://destination',
            id: 'pfxa4ada2aa-21ed-2788-7f49-e708fdaebc88'
          });

          done();
        });
      });
    });

    describe('when request is not a valid XML', function () {
      // There was a bug in xmldom causing an infinite loop in this case
      it('should return an empty object', function (done) {
        const req = '<samlp:AuthnRequest';
        samlp.parseRequest({
          query: {
            SAMLRequest: new Buffer(req).toString('base64'),
            RelayState: '123'
          }
        }, {
          relayState: '123'
        }, function (err, result) {
          expect(err).to.exist;
          expect(err.message).to.equal('expected null to exist');
          expect(result).to.be.undefined;
          done();
        });
      });
    });

    describe('when request is not a malformed XML', function () {
      it('should return an error', function (done) {
        const samlRequestPlain = '<samlp:AuthnRequest foo="bar"></test>';
        encodeAndDeflate(samlRequestPlain, function (err, req) {
          if (err) { return done(err); };

          samlp.parseRequest({
            query: {
              SAMLRequest: req.toString('base64'),
              RelayState: '123'
            }
          }, {
            relayState: '123'
          }, function (err, result) {
            expect(err).to.exist;
            expect(result).to.be.undefined;
            expect(err.message).to.equal('end tag name: test is not match the current start tagName:undefined');
            done();
          });

        });
      });
    });
  });
});


function encodeAndDeflate(xml, cb) {
  zlib.deflateRaw(new Buffer(xml), function (err, buffer) {
    if (err) { return cb(err); }
    cb(null, buffer.toString('base64'));
  });
};