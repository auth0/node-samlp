var xmlCrypto = require('xml-crypto'),
    xmldom = require('xmldom');
    
exports.verifySignature = function(assertion, cert) {
  try {
    var doc = new xmldom.DOMParser().parseFromString(assertion);
    var signature = xmlCrypto.xpath.SelectNodes(doc, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
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

exports.getDestination = function(response) {
  var doc = new xmldom.DOMParser().parseFromString(response);
  var destination = doc.documentElement.getAttribute('Destination');
  return destination;
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

exports.getConditions = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  return doc.documentElement.getElementsByTagName('saml:Conditions');
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

exports.getSubjectConfirmationData = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  return doc.documentElement.getElementsByTagName('saml:SubjectConfirmationData')[0];
};

exports.getAuthnContextClassRef = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  return doc.documentElement.getElementsByTagName('saml:AuthnContextClassRef')[0];
};
