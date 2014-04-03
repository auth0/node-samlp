var templates = require('./templates'),
    encoders = require('./encoders'),
    PassportProfileMapper = require('./claims/PassportProfileMapper'),
    saml20 = require('saml').Saml20,
    zlib = require('zlib'),
    xmldom = require('xmldom'),
    SignedXml = require('xml-crypto').SignedXml,
    xpath = require('xpath');

function getSamlRequest(samlRequest, callback) {
  if (!samlRequest) return callback();

  var input = new Buffer(samlRequest, 'base64');
  if (input[0] === 60) {  // open tag
    // content is just encoded, not zipped
    var xml = new xmldom.DOMParser().parseFromString(input.toString());
    callback(null, xml);
  } else {
    zlib.inflateRaw(input, function(err, buffer) {
      if (err) return callback(err);
      
      var xml = new xmldom.DOMParser().parseFromString(buffer.toString());
      callback(null, xml);
    });
  }
}

function getSamlResponse(options, user) {
  options.profileMapper = options.profileMapper || PassportProfileMapper;

  var profileMap = options.profileMapper(user);
  var claims = profileMap.getClaims(options);
  var ni = profileMap.getNameIdentifier(options);

  var signedAssertion = saml20.create({
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
    encryptionCert:       options.encryptionCert
  });
  
  var SAMLResponse = templates.samlresponse({
    id:             '_' + generateUniqueID(),
    instant:        generateInstant(),
    destination:    options.destination || options.audience,
    inResponseTo:   options.inResponseTo,
    issuer:         options.issuer,
    samlStatusCode: options.samlStatusCode || 'urn:oasis:names:tc:SAML:2.0:status:Success',
    assertion:      signedAssertion
  });

  if (options.signResponse) {
    
    var cannonicalized = SAMLResponse
                                    .replace(/\r\n/g, '')
                                    .replace(/\n/g,'')
                                    .replace(/>(\s*)</g, '><') //unindent
                                    .trim();
    
    var sig = new SignedXml(null, { signatureAlgorithm: algorithms.signature[options.signatureAlgorithm], idAttribute: 'ID' });
    sig.addReference("//*[local-name(.)='Response' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:protocol']",
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
 * 
 * @param  {[type]} options [description]
 * @return {[type]}         [description]
 */
module.exports.auth = function(options) {
  options = options || {};
  options.getUserFromRequest = options.getUserFromRequest || function(req){ return req.user; };
  options.signatureAlgorithm = options.signatureAlgorithm || 'rsa-sha256';
  options.digestAlgorithm = options.digestAlgorithm || 'sha256';
  
  if(typeof options.getPostURL !== 'function') {
    throw new Error('getPostURL is required');
  }

  function execute (postUrl, audience, req, res) {
    var user = options.getUserFromRequest(req);
    if(!user) return res.send(401);

    options.audience = options.audience || audience;
    
    var SAMLResponse = getSamlResponse(options, user);
    var response = new Buffer(SAMLResponse);

    res.set('Content-Type', 'text/html');
    res.send(templates.form({
      callback:        postUrl,
      RelayState:      options.RelayState || req.query.RelayState || req.body.RelayState || '',
      SAMLResponse:    response.toString('base64')
    }));
  }

  return function (req, res) {
    getSamlRequest(req.query.SAMLRequest || req.body.SAMLRequest, function(err, samlRequestDom) {
      if (samlRequestDom) {
        var issuer = xpath.select("//*[local-name(.)='Issuer' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:assertion']/text()", samlRequestDom);
        if (issuer && issuer.length > 0) options.audience = options.audience || issuer[0].textContent;

        var id = samlRequestDom.documentElement.getAttribute('ID');
        if (id) options.inResponseTo = options.inResponseTo || id;
      }

      options.getPostURL(options.audience, samlRequestDom, req, function (err, postUrl) {
        if (err) return res.send(500, err);
        if (!postUrl) return res.send(401);
        execute(postUrl, options.audience, req, res);
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

    var id = samlRequestDom.documentElement.getAttribute('ID');
    if (id) data.id = id;

    callback(null, data);
  });
};

module.exports.getSamlResponse = getSamlResponse;
