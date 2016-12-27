var zlib                  = require('zlib');
var xmldom                = require('xmldom');
var qs                    = require('querystring');
var xpath                 = require('xpath');
var url                   = require('url');
var xtend                 = require('xtend');
var signers               = require('./signers');
var constants             = require('./constants');

var algorithmSignatures = {
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': 'rsa-sha256',
  'http://www.w3.org/2000/09/xmldsig#rsa-sha1': 'rsa-sha1'
};

function shouldValidateSignature(options) {
  return options.signingCert || options.thumprints || options.getCredentials;
}

module.exports.parseSamlRequest = function(req, samlRequest, type, options, callback) {
  function checkSignature(xml, cb) {
    var opts = {
      signingCert: options.signingCert, 
      thumbprints: options.thumbprints,
      deflate: !!req.query.Signature
    };

    if (options.getCredentials) {
      var issuerNode = xpath.select(constants.ELEMENTS[type].ISSUER_PATH, xml);

      if (!issuerNode || issuerNode.length === 0) {
        return cb(new Error('SAML Request with no issuer. Issuer is a mandatory element.'));
      }

      var issuer = issuerNode[0].textContent;
      var credentials = options.getCredentials(issuer);
      opts.signingCert = credentials.cert;
      opts.thumbprints = credentials.thumbprints;
    }

    try{
      validateSignature(req, type, xml, opts);
      return cb(null, xml);
    } catch(e){
      return cb(e);
    }
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

      if (!shouldValidateSignature(options)) {
        return callback(null, xml);
      }

      checkSignature(xml, callback);
    } else {
      zlib.inflateRaw(input, function(err, buffer) {
        if (err) return callback(err);

        var xml = new xmldom.DOMParser().parseFromString(buffer.toString());
        if (!xml || !xml.documentElement) {
          return callback(new Error('Invalid SAML Request'));
        }

        if (!shouldValidateSignature(options)) {
          return callback(null, xml);
        }

        checkSignature(xml, callback);
      });
    }
  } catch(e) {    
    callback(e);
  }
};

module.exports.generateUniqueID = function() {
  var chars = "abcdef0123456789";
  var uniqueID = "";
  for (var i = 0; i < 20; i++) {
    uniqueID += chars.substr(Math.floor((Math.random()*15)), 1);
  }
  return uniqueID;
};

module.exports.generateInstant = function(){
  var date = new Date();
  return date.getUTCFullYear() + '-' + ('0' + (date.getUTCMonth()+1)).slice(-2) + '-' + ('0' + date.getUTCDate()).slice(-2) + 'T' + ('0' + date.getUTCHours()).slice(-2) + ":" + ('0' + date.getUTCMinutes()).slice(-2) + ":" + ('0' + date.getUTCSeconds()).slice(-2) + "Z";
};

module.exports.appendQueryString = function(initialUrl, query) {
  var parsed = url.parse(initialUrl, true);
  parsed.query = xtend(parsed.query, query);
  delete parsed.search;
  return url.format(parsed);
};

module.exports.getRoundTripDateFormat = function() {
  //http://msdn.microsoft.com/en-us/library/az4se3k1.aspx#Roundtrip
  var date = new Date();
  return date.getUTCFullYear() + '-' +
        ('0' + (date.getUTCMonth()+1)).slice(-2) + '-' +
        ('0' + date.getUTCDate()).slice(-2) + 'T' +
        ('0' + date.getUTCHours()).slice(-2) + ":" +
        ('0' + date.getUTCMinutes()).slice(-2) + ":" +
        ('0' + date.getUTCSeconds()).slice(-2) + "Z";
};

module.exports.validateSignature = validateSignature;

function validateSignature(req, element_type, xml, options) {
  var type = constants.ELEMENTS[element_type].PROP;

  var isRequestSigned = (req.body && req.body[type]) || !options.deflate ?
    xpath.select(options.signaturePath || constants.ELEMENTS[element_type].SIGNATURE_VALIDATION_PATH, xml).length > 0 : !!req.query.Signature;
  if (isRequestSigned) {
    if ((req.body && req.body[type]) || !options.deflate) {

      // HTTP-POST or HTTP-Redirect without deflate encoding
      var validationErrors = signers.validateXmlEmbeddedSignature(xml, options);
      if (validationErrors && validationErrors.length > 0) {
        throw new Error('Signature check errors: ' + validationErrors.join('; '));
      }
    }
    else {
      // HTTP-Redirect with deflate encoding
      var signedContent = {};
      signedContent[type] = req.query[type];
      signedContent.RelayState = req.query.RelayState || options.relayState;
      signedContent.SigAlg = req.query.SigAlg;

      if (!signedContent.RelayState && !options.relayState) {
        delete signedContent.RelayState;
      }

      if (!signedContent.SigAlg){
        throw new Error('Signature Algorithm is missing');
      }
      
      if (!algorithmSignatures[signedContent.SigAlg]){
        throw new Error('Invalid signature algorithm. Supported algorithms are http://www.w3.org/2001/04/xmldsig-more#rsa-sha1 and http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
      }

      var valid = signers.isValidContentAndSignature(qs.stringify(signedContent), req.query.Signature, {
        signingCert: options.signingCert,
        signatureAlgorithm: req.query.SigAlg
      });

      if (!valid) {
        throw new Error('Signature check errors: The signature provided (' + req.query.Signature + ') does not match the one calculated');
      }
    }
  } else if (type === 'SAMLRequest') {
    throw new Error('SAMLRequest message MUST be signed when using an asynchronous binding (POST or Redirect)');
  }
};