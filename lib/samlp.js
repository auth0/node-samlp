var saml20                = require('saml').Saml20;
var zlib                  = require('zlib');
var xmldom                = require('xmldom');
var SignedXml             = require('xml-crypto').SignedXml;
var xpath                 = require('xpath');
var xtend                 = require('xtend');

var templates             = require('./templates');
var encoders              = require('./encoders');
var PassportProfileMapper = require('./claims/PassportProfileMapper');

function getSamlRequest(samlRequest, callback) {
  if (!samlRequest) return callback();

  var input = new Buffer(samlRequest, 'base64');
  if (input[0] === 60) {  // open tag
    // content is just encoded, not zipped
    var xml = new xmldom.DOMParser().parseFromString(input.toString());
    if (!xml) return callback(new Error('Invalid SAML Request'));
    callback(null, xml);
  } else {
    zlib.inflateRaw(input, function(err, buffer) {
      if (err) return callback(err);

      var xml = new xmldom.DOMParser().parseFromString(buffer.toString());
      if (!xml) return callback(new Error('Invalid SAML Request'));
      callback(null, xml);
    });
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
      getKeyInfo: function () {
        return "<X509Data><X509Certificate>" + pem + "</X509Certificate></X509Data>";
      }
    };

    sig.computeSignature(cannonicalized);
    SAMLResponse = sig.getSignedXml();
  }

  return SAMLResponse;
}

function getSamlResponse(options, user, callback) {
  options.profileMapper = options.profileMapper || PassportProfileMapper;

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
    sessionIndex:         options.sessionIndex
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
      getKeyInfo: function () {
        return '<X509Data><X509Certificate>' + pem + '</X509Certificate></X509Data>';
      }
    };

    sig.computeSignature(cannonicalized);
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
 * - responseHandler(SAMLResponse, request, response, next) a function that handles the response. Defaults to HTML POST to postUrl.
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

    getSamlResponse(opts, user, function (err, SAMLResponse) {
      if (err) return next(err);

      var response = new Buffer(SAMLResponse);

      if (opts.responseHandler) {
        opts.responseHandler(response, req, res, next);
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
    getSamlRequest(req.query.SAMLRequest || req.body.SAMLRequest, function(err, samlRequestDom) {
      var audience = opts.audience;
      if (samlRequestDom) {
        var issuer = xpath.select("//*[local-name(.)='Issuer' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:assertion']/text()", samlRequestDom);
        if (issuer && issuer.length > 0) audience = audience || issuer[0].textContent;

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

module.exports.parseRequest = function(req, callback) {
  var samlRequest = req.query.SAMLRequest || req.body.SAMLRequest;
  if (!samlRequest)
    return callback();

  getSamlRequest(samlRequest, function(err, samlRequestDom) {
    if (err) return callback(err);

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
  var samlRequest = req.query.SAMLRequest || req.body.SAMLRequest;
  if (!samlRequest) return callback();

  getSamlRequest(samlRequest, function(err, logoutRequestDom) {
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
