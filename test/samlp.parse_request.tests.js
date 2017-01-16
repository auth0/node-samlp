'use strict'

var expect = require('chai').expect;
var samlp = require('../lib')
var encoder = require('../lib/encoders');
var fs = require('fs')
var path = require('path')

var requestWithAuthnContextClassRef = '<?xml version="1.0" encoding="UTF-8"?>\n<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="pfxe6c08b2b-e9a1-5d44-9016-f4c2b59add88" AssertionConsumerServiceURL="https://acs" Destination="https://destination" IssueInstant="2013-04-28T22:43:42.386Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://sp</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">\n  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>\n    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>\n  <ds:Reference URI="#pfxe6c08b2b-e9a1-5d44-9016-f4c2b59add88"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>1GJyc/S+0PTuqU1hp6grJy3u4Dk=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>MKsGyFxVQgCSLwkajqGZBKHskLVo/G1aj1V8PptruBwLBZ9nhMXgX8T+rmDuyTqbHUDfITRMXcREmIqbLyqvK4ICqU24TB4agHtRe9302BeNXCqVbtwQOuQGdjqAKHAIev+4Nd+74PblL5EBUMxnHcS0LavTisXvqab+70vnTn/Bhxqj+upBNyTGscqGpPxrZMqZzlwPpaCMCnDyBj3tyYdh+4iUrzmom3UBQuazpriezEYFa+6HNl0qi6umh9gEkaPjqC7z4HspvA5+R5ipS2zqk54Aq0bH9iFLstzc4BPENB2LrNEtC11xXo6opbk2p9sCeEMH0A/Dlc+LxbR5tg==</ds:SignatureValue>\n<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDtTCCAp2gAwIBAgIJAMKR/NsyfcazMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTIxMTEyMjM0MzQxWhcNMTYxMjIxMjM0MzQxWjBFMQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvtH4wKLYlIXZlfYQFJtXZVC3fD8XMarzwvb/fHUyJ6NvNStN+H7GHp3/QhZbSaRyqK5hu5xXtFLgnI0QG8oE1NlXbczjH45LeHWhPIdc2uHSpzXic78kOugMY1vng4J10PF6+T2FNaiv0iXeIQq9xbwwPYpflViQyJnzGCIZ7VGan6GbRKzyTKcB58yx24pJq+CviLXEY52TIW1l5imcjGvLtlCp1za9qBZa4XGoVqHi1kRXkdDSHty6lZWj3KxoRvTbiaBCH+75U7rifS6fR9lqjWE57bCGoz7+BBu9YmPKtI1KkyHFqWpxaJc/AKf9xgg+UumeqVcirUmAsHJrMwIDAQABo4GnMIGkMB0GA1UdDgQWBBTs83nkLtoXFlmBUts3EIxcVvkvcjB1BgNVHSMEbjBsgBTs83nkLtoXFlmBUts3EIxcVvkvcqFJpEcwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZIIJAMKR/NsyfcazMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBABw7w/5k4d5dVDgd/OOOmXdaaCIKvt7d3ntlv1SSvAoKT8d8lt97Dm5RrmefBI13I2yivZg5bfTge4+vAV6VdLFdWeFp1b/FOZkYUv6A8o5HW0OWQYVX26zIqBcG2Qrm3reiSl5BLvpj1WSpCsYvs5kaO4vFpMak/ICgdZD+rxwxf8Vb/6fntKywWSLgwKH3mJ+Z0kRlpq1g1oieiOm1/gpZ35s0YuorXZba9ptfLCYSggg/qc3d3d0tbHplKYkwFm7f5ORGHDSD5SJm+gI7RPE+4bO8q79RPAfbG1UGuJ0b/oigagciHhJp851SQRYf3JuNSc17BnK2L5IEtzjqr+Q=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/><samlp:RequestedAuthnContext Comparison="exact"><samlp:AuthnContextClassRef>http://schemas.openid.net/pape/policies/2007/06/multi-factor</samlp:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>';

var requestWithoutAuthnContextClassRef = '<?xml version="1.0" encoding="UTF-8"?>\n<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="pfx20d87357-f8ae-db44-a7a9-39c0446a2ee2" AssertionConsumerServiceURL="https://acs" Destination="https://destination" IssueInstant="2013-04-28T22:43:42.386Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://sp</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">\n  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>\n    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>\n  <ds:Reference URI="#pfx20d87357-f8ae-db44-a7a9-39c0446a2ee2"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>HB+gsJjEBYtMgMwznLms7tXAmmo=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>mt6/9/JW8wsk72FaATq5Xp+TIartEZlDCo+Y8DWCenxoE1KXP0YKP4btEoTO3yop/l9JNMEJm7rONYbLZ+WxpjObCRbuVfmFpS4NNUyEiCTMzaDvzd0ipGpD0Zd/m719cwdhlxe6GjNHBWSmgjW/ojJPtb0aeuwCa3i2rv71R28DPOfLL1324V8YuDyqukqoOMfMI7NMUW5Wklh+AqhIp/rmin4SGQRc6Ccj9judPHQsijws9PtKoWMnWC9mVLd7sRcRY5yXissnnT8v4kH2haG1usu+t3HojhZ/symC9o7cmQJauyJyNLTx5Cl+4tokqwI3amK0gDhhoR0Q2cRxTg==</ds:SignatureValue>\n<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDtTCCAp2gAwIBAgIJAMKR/NsyfcazMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTIxMTEyMjM0MzQxWhcNMTYxMjIxMjM0MzQxWjBFMQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvtH4wKLYlIXZlfYQFJtXZVC3fD8XMarzwvb/fHUyJ6NvNStN+H7GHp3/QhZbSaRyqK5hu5xXtFLgnI0QG8oE1NlXbczjH45LeHWhPIdc2uHSpzXic78kOugMY1vng4J10PF6+T2FNaiv0iXeIQq9xbwwPYpflViQyJnzGCIZ7VGan6GbRKzyTKcB58yx24pJq+CviLXEY52TIW1l5imcjGvLtlCp1za9qBZa4XGoVqHi1kRXkdDSHty6lZWj3KxoRvTbiaBCH+75U7rifS6fR9lqjWE57bCGoz7+BBu9YmPKtI1KkyHFqWpxaJc/AKf9xgg+UumeqVcirUmAsHJrMwIDAQABo4GnMIGkMB0GA1UdDgQWBBTs83nkLtoXFlmBUts3EIxcVvkvcjB1BgNVHSMEbjBsgBTs83nkLtoXFlmBUts3EIxcVvkvcqFJpEcwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZIIJAMKR/NsyfcazMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBABw7w/5k4d5dVDgd/OOOmXdaaCIKvt7d3ntlv1SSvAoKT8d8lt97Dm5RrmefBI13I2yivZg5bfTge4+vAV6VdLFdWeFp1b/FOZkYUv6A8o5HW0OWQYVX26zIqBcG2Qrm3reiSl5BLvpj1WSpCsYvs5kaO4vFpMak/ICgdZD+rxwxf8Vb/6fntKywWSLgwKH3mJ+Z0kRlpq1g1oieiOm1/gpZ35s0YuorXZba9ptfLCYSggg/qc3d3d0tbHplKYkwFm7f5ORGHDSD5SJm+gI7RPE+4bO8q79RPAfbG1UGuJ0b/oigagciHhJp851SQRYf3JuNSc17BnK2L5IEtzjqr+Q=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/></samlp:AuthnRequest>';

describe('samlp parse response', function() {
  var cert;

  before(function () {
    cert = fs.readFileSync(path.join(__dirname, 'fixture/samlp.test-cert.pem'));
  });

  describe('SAMLRequest on querystring', function () {
    let parseResult;

    describe('when request has authnContextClassRef', function() {
      it('should return a valid response', function(done){
        samlp.parseRequest({
          query: {
            SAMLRequest: new Buffer(requestWithAuthnContextClassRef).toString('base64'),
            RelayState: '123'
          }
        }, {
          signingCert: cert,
          thumbprints: [ encoder.thumbprint(cert) ],
          relayState: '123'
        }, function(err, result) {
          expect(err).not.to.exist;
          expect(result).to.eql({
            issuer: 'http://sp',
            assertionConsumerServiceURL: 'https://acs',
            destination: 'https://destination',
            id: 'pfxe6c08b2b-e9a1-5d44-9016-f4c2b59add88',
            requestedAuthnContext: {
              authnContextClassRef: 'http://schemas.openid.net/pape/policies/2007/06/multi-factor'
            }
          });

          done();
        })
      });
    });

    describe('when request does not have authnContextClassRef', function() {
      it('should return a valid response', function(done){
        samlp.parseRequest({
            query: {
              SAMLRequest: new Buffer(requestWithoutAuthnContextClassRef).toString('base64'),
              RelayState: '123'
            }
          }, {
            signingCert: cert,
            thumbprints: [ encoder.thumbprint(cert) ],
            relayState: '123'
          }, function(err, result) {
            if (err) {
              done(err);
              return;
            }

            expect(err).not.to.exist;
            expect(result).to.eql({
              issuer: 'http://sp',
              assertionConsumerServiceURL: 'https://acs',
              destination: 'https://destination',
              id: 'pfx20d87357-f8ae-db44-a7a9-39c0446a2ee2'
            });

            done();
          });
      });
    });
  });
});
