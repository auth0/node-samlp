var xmlCrypto = require('xml-crypto');
var xmldom = require('@auth0/xmldom');

exports.verifySignature = function(assertion, cert) {
  try {
    var doc = new xmldom.DOMParser().parseFromString(assertion);
    var signature = xmlCrypto.xpath(doc, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
    var sig = new xmlCrypto.SignedXml(null, { idAttribute: 'AssertionID' });
    sig.keyInfoProvider = {
      getKeyInfo: function (key) {
        return "<X509Data></X509Data>";
      },
      getKey: function (keyInfo) {
        return cert;
      }
    };
    sig.loadSignature(signature.toString());
    var result = sig.checkSignature(assertion);

    if (!result) {
      console.log(sig.validationErrors);
    }

    return result;
  } catch (e) {
    console.log(e);
    return false;
  }

};

exports.getIssuer = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  var issuer = doc.documentElement.getElementsByTagName('saml:Issuer');
  return issuer[0].textContent;
};

exports.getElementText = function(assertion, elementName) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  var element = doc.documentElement.getElementsByTagName(elementName);
  return element[0].textContent;
};

exports.getDestination = function(response) {
  var doc = new xmldom.DOMParser().parseFromString(response);
  var destination = doc.documentElement.getAttribute('Destination');
  return destination;
};

exports.getInResponseTo = function(response) {
  var doc = new xmldom.DOMParser().parseFromString(response);
  var destination = doc.documentElement.getAttribute('InResponseTo');
  return destination;
};

exports.getStatusCode = function(response) {
  var doc = new xmldom.DOMParser().parseFromString(response);
  var status = doc.documentElement
                  .getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol', 'StatusCode')[0]
                  .getAttribute('Value');
  return status;
};

exports.getStatusMessage = function(response) {
  var doc = new xmldom.DOMParser().parseFromString(response);
  var message = doc.documentElement
                  .getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol', 'StatusMessage')[0]
                  .textContent;
  return message;
};

exports.getSignatureMethodAlgorithm = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  return doc.documentElement
            .getElementsByTagName('SignatureMethod')[0]
            .getAttribute('Algorithm');
};

exports.getDigestMethodAlgorithm = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  return doc.documentElement
            .getElementsByTagName('DigestMethod')[0]
            .getAttribute('Algorithm');
};

exports.getIssueInstant = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  return doc.documentElement.getAttribute('IssueInstant');
};

/**
 * @param {String} assertion
 * @return {number} the instant in milliseconds since the Epoch
 */
exports.getIssueInstantUTC = function(assertion) {
  return new Date(exports.getIssueInstant(assertion)).getTime();
};

exports.getConditions = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  return doc.documentElement.getElementsByTagName('saml:Conditions');
};

exports.getConsent = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  return doc.documentElement.getAttribute('Consent');
};

exports.getAudiences = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  return doc.documentElement
            .getElementsByTagName('saml:Conditions')[0]
            .getElementsByTagName('saml:AudienceRestriction')[0]
            .getElementsByTagName('saml:Audience');
};

exports.getAttributes = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  return doc.documentElement
            .getElementsByTagName('saml:Attribute');
};

exports.getNameIdentifier = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  return doc.documentElement
            .getElementsByTagName('saml:NameID')[0];
};

exports.getNameIdentifierFormat = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  return doc.documentElement
            .getElementsByTagName('NameID')[0]
            .getAttribute('Format');
};

exports.getSubjectConfirmationData = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  return doc.documentElement.getElementsByTagName('saml:SubjectConfirmationData')[0];
};

exports.getAuthnContextClassRef = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  return doc.documentElement.getElementsByTagName('saml:AuthnContextClassRef')[0];
};
