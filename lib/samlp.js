var saml20                = require('saml').Saml20;
var zlib                  = require('zlib');
var xmldom                = require('xmldom');
var crypto                = require('crypto');
var SignedXml             = require('xml-crypto').SignedXml;
var xpath                 = require('xpath');
var xtend                 = require('xtend');
var querystring           = require('querystring');

var templates             = require('./templates');
var encoders              = require('./encoders');
var PassportProfileMapper = require('./claims/PassportProfileMapper');

var signaturePath = "//*[local-name(.)='AuthnRequest']/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']";
var algorithmSignatures = {
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': 'rsa-sha256',
  'http://www.w3.org/2000/09/xmldsig#rsa-sha1': 'rsa-sha1'
};

function parseSamlRequest(samlRequest, options, callback) {
  if (typeof options === 'function'){
    callback = options;
    options = {};
  }

  if (!samlRequest) return callback();
  
  try {
    var input = new Buffer(samlRequest, 'base64');
    
    if (input[0] === 60) {  // open tag
      // content is just encoded, not zipped
      var xml = new xmldom.DOMParser().parseFromString(input.toString());
      if (!xml || !xml.documentElement) {
        return callback(new Error('Invalid SAML Request'));
      }

      if (!options.signingCert && !options.thumprints){
        return callback(null, xml);
      }

      validateXmlSignature(xml, { cert: options.signingCert, thumbprints: options.thumbprints }, callback);
    } else {
      zlib.inflateRaw(input, function(err, buffer) {
        if (err) return callback(err);

        var xml = new xmldom.DOMParser().parseFromString(buffer.toString());
        if (!xml || !xml.documentElement) {
          return callback(new Error('Invalid SAML Request'));
        }

        if (!options.signingCert && !options.thumprints){
          return callback(null, xml);
        }
        
        // Http-Redirect binding can have the signature in query instead of in the AuthnRequest
        // We pass the signature and algorithm if found.
        if (options.signature){
          if (!options.sigAlg){
            return callback(new Error('Signature Algorithm is missing'));
          }
          
          if (!algorithmSignatures[options.sigAlg]){
            return callback(new Error('Invalid signature algorithm. Supported algorithms are http://www.w3.org/2001/04/xmldsig-more#rsa-sha1 and http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'));
          }

          if (!options.signingCert){
            return callback(new Error('Make sure you configure the signing certificate to be able to validate the SAML Request'));
          }

          // The order in which we add the attributes to the signedParams is important
          // querystring.stringify() uses insertion order
          var signedParams =  {
            SAMLRequest: samlRequest,
          }; 
        
          if (options.relayState){
            signedParams.RelayState = options.relayState;
          }

          signedParams.SigAlg = options.sigAlg;

          try{
            // Compare signatures
            return validateSignature(options.signature, querystring.stringify(signedParams), certToPEM(options.signingCert), algorithmSignatures[options.sigAlg]) ?
              callback(null, xml) :
              callback(new Error('Signature check errors: The signature provided (' + options.signature + ') does not match the one calculated'));
          } catch(e){
            return callback(e);
          }
        }

        validateXmlSignature(xml, { cert: options.signingCert, thumbprints: options.thumbprints }, callback);
      });
    }
  } catch(e) {    
    callback(e);
  }
}

function buildSamlResponse(options) {
  var SAMLResponse = templates.samlresponse({
    id:             '_' + generateUniqueID(),
    instant:        generateInstant(),
    destination:    options.destination || options.audience,
    inResponseTo:   options.inResponseTo,
    issuer:         options.issuer,
    samlStatusCode: options.samlStatusCode,
    samlStatusMessage: options.samlStatusMessage,
    assertion:      options.signedAssertion || ''
  });

  if (options.signResponse) {
    options.signatureNamespacePrefix = typeof options.signatureNamespacePrefix === 'string' ? options.signatureNamespacePrefix : '' ;

    var cannonicalized = SAMLResponse
      .replace(/\r\n/g, '')
      .replace(/\n/g,'')
      .replace(/>(\s*)</g, '><') //unindent
      .trim();

    var sig = new SignedXml(null, {
      signatureAlgorithm: algorithms.signature[options.signatureAlgorithm],
      idAttribute: 'ID'
    });

    sig.addReference(
      "//*[local-name(.)='Response' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:protocol']",
      ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"],
      algorithms.digest[options.digestAlgorithm]);

    sig.signingKey = options.key;

    var pem = encoders.removeHeaders(options.cert);
    sig.keyInfoProvider = {
      getKeyInfo: function (key, prefix) {
        prefix = prefix ? prefix + ':' : prefix;
        return "<" + prefix + "X509Data><" + prefix + "X509Certificate>" + pem + "</" + prefix + "X509Certificate></" + prefix + "X509Data>";
      }
    };

    sig.computeSignature(cannonicalized, { prefix: options.signatureNamespacePrefix });
    SAMLResponse = sig.getSignedXml();
  }

  return SAMLResponse;
}

function getSamlResponse(options, user, callback) {
  options.profileMapper = options.profileMapper || PassportProfileMapper;
  options.signatureNamespacePrefix = typeof options.signatureNamespacePrefix === 'string' ? options.signatureNamespacePrefix : '' ;

  var profileMap = options.profileMapper(user);
  var claims = profileMap.getClaims(options);
  var ni = profileMap.getNameIdentifier(options);

  if (!ni || !ni.nameIdentifier) {
    var error = new Error('No attribute was found to generate the nameIdentifier. We tried with: ' + (options.nameIdentifierProbes || []).join(', '));
    error.context = { user: user };
    return callback(error);
  }

  saml20.create({
    signatureAlgorithm:   options.signatureAlgorithm,
    digestAlgorithm:      options.digestAlgorithm,
    cert:                 options.cert,
    key:                  options.key,
    issuer:               options.issuer,
    lifetimeInSeconds:    options.lifetimeInSeconds || 3600,
    audiences:            options.audience,
    attributes:           claims,
    nameIdentifier:       ni.nameIdentifier,
    nameIdentifierFormat: ni.nameIdentifierFormat || options.nameIdentifierFormat,
    recipient:            options.recipient,
    inResponseTo:         options.inResponseTo,
    authnContextClassRef: options.authnContextClassRef,
    encryptionPublicKey:  options.encryptionPublicKey,
    encryptionCert:       options.encryptionCert,
    sessionIndex:         options.sessionIndex,
    typedAttributes:      options.typedAttributes,
    includeAttributeNameFormat:    options.includeAttributeNameFormat,
    signatureNamespacePrefix:      options.signatureNamespacePrefix
  }, function (err, signedAssertion) {
    if (err) return callback(err);

    options.signedAssertion = signedAssertion;
    options.samlStatusCode = options.samlStatusCode || 'urn:oasis:names:tc:SAML:2.0:status:Success';
    var SAMLResponse = buildSamlResponse(options);
    callback(null, SAMLResponse);
  });
}

function getLogoutResponse (options, callback) {
  var logoutResponse = templates.logoutresponse({
    id:             '_' + generateUniqueID(),
    instant:        generateInstant(),
    destination:    options.destination || options.audience,
    inResponseTo:   options.inResponseTo,
    issuer:         options.issuer,
    samlStatusCode: options.samlStatusCode || 'urn:oasis:names:tc:SAML:2.0:status:Success'
  });

  if (options.signResponse) {
    options.signatureNamespacePrefix = typeof options.signatureNamespacePrefix === 'string' ? options.signatureNamespacePrefix : '' ;
    
    // sign response and add embedded signature
    var cannonicalized = logoutResponse
      .replace(/\r\n/g, '')
      .replace(/\n/g,'')
      .replace(/>(\s*)</g, '><') //unindent
      .trim();

    var sig = new SignedXml(null, { signatureAlgorithm: algorithms.signature[options.signatureAlgorithm], idAttribute: 'ID' });
    sig.addReference("//*[local-name(.)='LogoutResponse' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:protocol']",
      ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/2001/10/xml-exc-c14n#'],
      algorithms.digest[options.digestAlgorithm]);

    sig.signingKey = options.key;

    var pem = encoders.removeHeaders(options.cert);
    sig.keyInfoProvider = {
      getKeyInfo: function (key, prefix) {
        prefix = prefix ? prefix + ':' : prefix;
        return "<" + prefix + "X509Data><" + prefix + "X509Certificate>" + pem + "</" + prefix + "X509Certificate></" + prefix + "X509Data>";
      }
    };

    sig.computeSignature(cannonicalized, { prefix: options.signatureNamespacePrefix });
    logoutResponse = sig.getSignedXml();
  }

  callback(null, logoutResponse);
}

function generateUniqueID() {
  var chars = "abcdef0123456789";
  var uniqueID = "";
  for (var i = 0; i < 20; i++) {
    uniqueID += chars.substr(Math.floor((Math.random()*15)), 1);
  }
  return uniqueID;
}

function generateInstant() {
  var date = new Date();
  return date.getUTCFullYear() + '-' + ('0' + (date.getUTCMonth()+1)).slice(-2) + '-' + ('0' + date.getUTCDate()).slice(-2) + 'T' + ('0' + date.getUTCHours()).slice(-2) + ":" + ('0' + date.getUTCMinutes()).slice(-2) + ":" + ('0' + date.getUTCSeconds()).slice(-2) + "Z";
}

// Validates an XML that contains a Signature element (signature inside XML)
function validateXmlSignature(xml, options, callback) {
  var calculatedThumbprint = '';
  var signature = options.signature || xpath.select(signaturePath, xml)[0];
  if (!signature){
    return callback(new Error('Signature is missing (xpath: ' + signaturePath + ')'));
  }

  if (options.thumprints){
    // Make sure thumprints is an array for the validation 
    options.thumbprints = options.thumbprints instanceof Array ? options.thumbprints : [options.thumbprints];
  }

  var sig = new SignedXml(null, { idAttribute: 'AssertionID' });

  sig.keyInfoProvider = {
    getKeyInfo: function () {
      return "<X509Data></X509Data>";
    },
    getKey: function (keyInfo) {

      //If there's no embedded signing cert, use the configured cert through options
      if(!keyInfo || keyInfo.length===0){
        if(!options.cert) throw new Error('options.cert must be specified for SAMLResponses with no embedded signing certificate');
        return certToPEM(options.cert);
      }

      //If there's an embedded signature and thumprints are provided check that
      if (options.thumbprints && options.thumbprints.length > 0)  {
        var embeddedSignature = keyInfo[0].getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "X509Certificate");
        if (embeddedSignature.length > 0) {
          var base64cer = embeddedSignature[0].firstChild.toString();
          var shasum = crypto.createHash('sha1');
          var der = new Buffer(base64cer, 'base64').toString('binary');
          shasum.update(der);
          calculatedThumbprint = shasum.digest('hex');
          
          // using embedded cert, so options.cert is not used anymore
          delete options.cert;
          return certToPEM(base64cer);
        }
      }

      // If there's an embedded signature, but no thumprints are supplied, use options.cert
      // either options.cert or options.thumbprints must be specified so at this point there
      // must be an options.cert
      return certToPEM(options.cert);
    }
  };

  var valid;

  try {
    sig.loadSignature(signature);
    valid = sig.checkSignature(xml.toString());
  } catch (e) {
    return callback(e);
  }


  if (!valid) {
    return callback(new Error('Signature check errors: ' + sig.validationErrors));
  }

  if (options.cert) {
    return callback(null, xml);
  }

  if (options.thumbprints) {
    var valid_thumbprint = options.thumbprints.some(function (thumbprint) {
      return calculatedThumbprint.toUpperCase() === thumbprint.toUpperCase();
    });

    if (!valid_thumbprint) {
      return callback(new Error('Invalid thumbprint (configured: ' + options.thumbprints.join(', ').toUpperCase() + '. calculated: ' + calculatedThumbprint.toUpperCase() + ')' ));
    }

    return callback(null, xml);
  }
}

// Validates that the signature provided is ok (Used for HTTP-Redirect binding where the signature is sent in query string parameter)
function validateSignature(signature, content, key, algorithm) {
  var verifier = crypto.createVerify(algorithm.toUpperCase());
  verifier.update(content);
  return verifier.verify(key, signature, 'base64');
}

function certToPEM(cert) {
  if (/-----BEGIN CERTIFICATE-----/.test(cert)) {
    return cert;
  }

  cert = cert.match(/.{1,64}/g).join('\n');
  cert = "-----BEGIN CERTIFICATE-----\n" + cert;
  cert = cert + "\n-----END CERTIFICATE-----\n";
  return cert;
}

var algorithms = {
  signature: {
    'rsa-sha256': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    'rsa-sha1':  'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
  },
  digest: {
    'sha256': 'http://www.w3.org/2001/04/xmlenc#sha256',
    'sha1': 'http://www.w3.org/2000/09/xmldsig#sha1'
  }
};

/**
 * SAML Protocol middleware.
 *
 * This middleware creates a SAML endpoint based on the user logged in identity.
 *
 * options:
 * - profileMapper(profile) a ProfileMapper implementation to convert a user profile to claims  (PassportProfile).
 * - getUserFromRequest(req) a function that given a request returns the user. By default req.user
 * - issuer string
 * - cert the public certificate
 * - key the private certificate to sign all tokens
 * - postUrl function (SAMLRequest, request, callback)
 * - responseHandler(SAMLResponse, options, request, response, next) a function that handles the response. Defaults to HTML POST to postUrl.
 *
 * @param  {[type]} options [description]
 * @return {[type]}         [description]
 */
module.exports.auth = function(options) {
  var opts = xtend({}, options || {}); // clone options
  opts.getUserFromRequest = opts.getUserFromRequest || function(req){ return req.user; };
  opts.signatureAlgorithm = opts.signatureAlgorithm || 'rsa-sha256';
  opts.digestAlgorithm = opts.digestAlgorithm || 'sha256';

  if (typeof opts.getPostURL !== 'function') {
    throw new Error('getPostURL is required');
  }

  function execute (postUrl, audience, req, res, next) {
    var user = opts.getUserFromRequest(req);
    if (!user) return res.send(401);

    opts.audience = audience;
    opts.postUrl = postUrl;

    getSamlResponse(opts, user, function (err, SAMLResponse) {
      if (err) return next(err);

      var response = new Buffer(SAMLResponse);

      if (opts.responseHandler) {
        opts.responseHandler(response, opts, req, res, next);
      } else {
        res.set('Content-Type', 'text/html');
        res.send(templates.form({
          callback:        postUrl,
          RelayState:      opts.RelayState || (req.query || {}).RelayState || (req.body || {}).RelayState || '',
          SAMLResponse:    response.toString('base64')
        }));
      }
    });
  }

  return function (req, res, next) {
    if(req.method === 'GET' && req.query.Signature){
      opts.signature = req.query.Signature;
      opts.sigAlg = req.query.SigAlg;
      opts.relayState = opts.RelayState || req.query.RelayState;
    }

    parseSamlRequest((req.query || {}).SAMLRequest || (req.body || {}).SAMLRequest, opts, function(err, samlRequestDom) {
      if (err) return next(err);

      var audience = opts.audience;
      if (samlRequestDom) {
        if (!audience){
          var issuer = xpath.select("//*[local-name(.)='Issuer' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:assertion']/text()", samlRequestDom);
          if (issuer && issuer.length > 0) 
            audience = issuer[0].textContent;
        }

        var id = samlRequestDom.documentElement.getAttribute('ID');
        if (id) opts.inResponseTo = opts.inResponseTo || id;
      }

      opts.getPostURL(audience, samlRequestDom, req, function (err, postUrl) {
        if (err) { return res.send(500, err); }
        if (!postUrl) { return res.send(401); }

        execute(postUrl, audience, req, res, next);
      });
    });
  };
};

module.exports.parseRequest = function(req, options, callback) {
  if (typeof options === 'function'){
    callback = options;
    options = {};
  }

  var samlRequest = (req.query || {}).SAMLRequest || (req.body || {}).SAMLRequest;
  if (!samlRequest)
    return callback();

  // Http-Redirect binding sends signature in query string params
  if(req.method === 'GET' && req.query.Signature){
    options.signature = req.query.Signature;
    options.sigAlg = req.query.SigAlg;
    options.relayState = options.relayState || req.query.RelayState;
  }

  parseSamlRequest(samlRequest, options, function(err, samlRequestDom) {
    if (err) {
      return callback(err);
    }

    var data = {};
    var issuer = xpath.select("//*[local-name(.)='Issuer' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:assertion']/text()", samlRequestDom);
    if (issuer && issuer.length > 0) data.issuer = issuer[0].textContent;

    var assertionConsumerUrl = samlRequestDom.documentElement.getAttribute('AssertionConsumerServiceURL');
    if (assertionConsumerUrl) data.assertionConsumerServiceURL = assertionConsumerUrl;

    var destination = samlRequestDom.documentElement.getAttribute('Destination');
    if (destination) data.destination = destination;

    var forceAuthn = samlRequestDom.documentElement.getAttribute('ForceAuthn');
    if (forceAuthn) data.forceAuthn = forceAuthn;

    var id = samlRequestDom.documentElement.getAttribute('ID');
    if (id) data.id = id;

    callback(null, data);
  });
};

module.exports.logout = function (options) {
  function execute (postUrl, logoutRequestData, req, res, next) {
    options.inResponseTo = options.inResponseTo || logoutRequestData.id;

    getLogoutResponse(options, function (err, logoutResponse) {
      if (err) return next(err);

      res.set('Content-Type', 'text/html');
      res.send(templates.form({
        callback:     postUrl,
        RelayState:   options.RelayState || (req.query || {}).RelayState || (req.body || {}).RelayState || '',
        SAMLResponse: new Buffer(logoutResponse).toString('base64')
      }));
    });
  }

  return function (req, res, next) {
    module.exports.parseLogoutRequest(req, function (err, logoutRequestData) {
      if (err) { return res.send(500, err); }
      if (!logoutRequestData) { return res.send(400, 'missing SAMLRequest'); }

      // TODO #1: validate LogoutRequest and if valid, find out the associate SSO session for given
      // logoutRequestData.sessionIndex and that also is matched with logoutRequestData.nameID
      // TODO #2: sends LogoutRequest to each SP (another session participant) with corresponding SessionIndex and NameID
      options.getPostURL(logoutRequestData, req, function (err, postUrl) {
        if (err) { return res.send(500, err); }
        if (!postUrl) { return res.send(401); }
        execute(postUrl, logoutRequestData, req, res, next);
      });
    });
  };
};

module.exports.parseLogoutRequest = function (req, callback) {
  var samlRequest = (req.query || {}).SAMLRequest || (req.body || {}).SAMLRequest;
  if (!samlRequest) return callback();

  parseSamlRequest(samlRequest, function(err, logoutRequestDom) {
    if (err) return callback(err);

    var data = {};
    var issuer = xpath.select("//*[local-name(.)='Issuer' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:assertion']/text()", logoutRequestDom);
    if (issuer && issuer.length > 0) data.issuer = issuer[0].textContent;

    var sessionIndex = xpath.select("//*[local-name(.)='SessionIndex']/text()", logoutRequestDom);
    if (sessionIndex && sessionIndex.length > 0) data.sessionIndex = sessionIndex[0].textContent;

    var nameId = xpath.select("//*[local-name(.)='NameID']", logoutRequestDom);
    if (nameId && nameId.length > 0) {
      data.nameId = nameId[0].textContent;
      data.nameIdFormat = nameId[0].getAttribute('Format');
    }

    var destination = logoutRequestDom.documentElement.getAttribute('Destination');
    if (destination) data.destination = destination;

    var id = logoutRequestDom.documentElement.getAttribute('ID');
    if (id) data.id = id;

    callback(null, data);
  });
};

module.exports.getSamlResponse = getSamlResponse;

module.exports.sendError = function (options) {
  // https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
  function renderResponse(res, postUrl) {
    var error = options.error || {};
    options.samlStatusCode = error.code || 'urn:oasis:names:tc:SAML:2.0:status:Responder';
    options.samlStatusMessage = error.description;

    var SAMLResponse = buildSamlResponse(options);
    var response = new Buffer(SAMLResponse);

    res.set('Content-Type', 'text/html');
    res.send(templates.form({
      callback:     postUrl,
      RelayState:   options.RelayState,
      SAMLResponse: response.toString('base64')
    }));
  }

  return function (req, res, next) {
    options.getPostURL(req, function (err, postUrl) {
      if (err) return next(err);
      if (!postUrl) return next(new Error('postUrl is required'));
      renderResponse(res, postUrl);
    });
  };
};