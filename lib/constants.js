module.exports.BINDINGS = {
  HTTP_POST:      'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
  HTTP_REDIRECT:  'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
};

module.exports.STATUS = {
  SUCCESS: 'urn:oasis:names:tc:SAML:2.0:status:Success',
  PARTIAL_LOGOUT: 'urn:oasis:names:tc:SAML:2.0:status:PartialLogout',
  RESPONDER: 'urn:oasis:names:tc:SAML:2.0:status:Responder'
};

module.exports.ELEMENTS = {
  LOGOUT_REQUEST: {
    PROP: 'SAMLRequest',
    SIGNATURE_VALIDATION_PATH : "//*[local-name(.)='LogoutRequest']/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
    SIGNATURE_LOCATION_PATH : "//*[local-name(.)='LogoutRequest' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:protocol']",
    ISSUER_PATH : "//*[local-name(.)='Issuer' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:assertion']/text()",
    SESSION_INDEX_PATH: "//*[local-name(.)='SessionIndex' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:protocol']/text()",
    NAME_ID: "//*[local-name(.)='NameID' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:assertion']/text()"
  },
  LOGOUT_RESPONSE: {
    PROP: 'SAMLResponse',
    SIGNATURE_VALIDATION_PATH : "//*[local-name(.)='LogoutResponse']/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
    SIGNATURE_LOCATION_PATH: "//*[local-name(.)='LogoutResponse' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:protocol']"
  },
  RESPONSE: {
    PROP: 'SAMLResponse',
    SIGNATURE_LOCATION_PATH:  "//*[local-name(.)='Response' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:protocol']"
  },
  AUTHN_REQUEST: {
    PROP: 'SAMLRequest',
    SIGNATURE_VALIDATION_PATH :"//*[local-name(.)='AuthnRequest']/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
    AUTHN_CONTEXT_CLASS_REF_PATH : "//*[local-name(.)='AuthnContextClassRef']/text()"
  },
};

module.exports.ALGORITHMS = {
  SIGNATURE: {
    'rsa-sha256': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    'rsa-sha1':  'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
  },
  DIGEST: {
    'sha256': 'http://www.w3.org/2001/04/xmlenc#sha256',
    'sha1': 'http://www.w3.org/2000/09/xmldsig#sha1'
  }
};
