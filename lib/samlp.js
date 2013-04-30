var templates = require('./templates');
var PassportProfileMapper = require('./claims/PassportProfileMapper');
var saml20 = require('saml').Saml20;
var zlib = require('zlib');
var xmldom = require('xmldom');
var xpath = require('xpath');

function getAudience(samlRequest, callback) {
  if (!samlRequest) callback();

  var input = new Buffer(samlRequest, 'base64');
  zlib.inflateRaw(input, function(err, buffer) {
    if (err) return callback(err);
    var xml = new xmldom.DOMParser().parseFromString(buffer.toString());
    var audience = xpath.select("//*[local-name(.)='Issuer' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:assertion']/text()", xml);

    callback(null, audience);
  });
}

function generateUniqueID() {
  var chars = "abcdef0123456789";
  var uniqueID = "";
  for (var i = 0; i < 20; i++) {
    uniqueID += chars.substr(Math.floor((Math.random()*15)), 1);
  }
  return uniqueID;
};

function generateInstant() {
  var date = new Date();
  return date.getUTCFullYear() + '-' + ('0' + (date.getUTCMonth()+1)).slice(-2) + '-' + ('0' + date.getUTCDate()).slice(-2) + 'T' + ('0' + date.getUTCHours()).slice(-2) + ":" + ('0' + date.getUTCMinutes()).slice(-2) + ":" + ('0' + date.getUTCSeconds()).slice(-2) + "Z";
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
module.exports = function(options) {
  options = options || {};
  options.profileMapper = options.profileMapper || PassportProfileMapper;
  options.getUserFromRequest = options.getUserFromRequest || function(req){ return req.user; };
  
  if(typeof options.getPostURL !== 'function') {
    throw new Error('getPostURL is required');
  }

  function execute (postUrl, req, res) {
    getAudience(req.query.SAMLRequest, function(err, audience) {
      if (err) return res.send(500, err.toString());

      audience =  options.audience || audience;
          
      if(!audience){
        return res.send(400, 'unknown audience');
      }

      var user = options.getUserFromRequest(req);
      
      if(!user) return res.send(401);
      var profileMap = options.profileMapper(user);

      var claims = profileMap.getClaims();
      var ni = profileMap.getNameIdentifier();
      
      var signedAssertion = saml20.create({  
        signatureAlgorithm:   options.signatureAlgorithm,
        digestAlgorithm:      options.digestAlgorithm,
        cert:                 options.cert,
        key:                  options.key,
        issuer:               options.issuer,
        lifetimeInSeconds:    3600,
        audiences:            audience,
        attributes:           claims,
        nameIdentifier:       ni.nameIdentifier,
        nameIdentifierFormat: ni.nameIdentifierFormat
      });
      
      res.set('Content-Type', 'text/html');

      var SAMLResponse = templates.samlresponse({
        id:             '_' + generateUniqueID(),
        instant:        generateInstant(),
        destination:    audience,
        issuer:         options.issuer,
        samlStatusCode: 'urn:oasis:names:tc:SAML:2.0:status:Success',
        assertion:      signedAssertion 
      });

      res.send(templates.form({
        callback:        postUrl,
        RelayState:      options.RelayState || req.query.RelayState,
        SAMLResponse:    SAMLResponse
      }));
    });
  }

  return function (req, res) {
    options.getPostURL(req.query.wtrealm, req.query.wreply, req, function (err, postUrl) {
      if (err) return res.send(500, err);
      if (!postUrl) return res.send(401);
      execute(postUrl, req, res);
    });
  };
};