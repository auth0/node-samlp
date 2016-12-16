var zlib                  = require('zlib');
var xmldom                = require('xmldom');
var crypto                = require('crypto');
var SignedXml             = require('xml-crypto').SignedXml;
var qs                    = require('querystring');
var xpath                 = require('xpath');
var url                   = require('url');
var xtend                 = require('xtend');

var signaturePath = "//*[local-name(.)='AuthnRequest']/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']";
var algorithmSignatures = {
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': 'rsa-sha256',
  'http://www.w3.org/2000/09/xmldsig#rsa-sha1': 'rsa-sha1'
};

module.exports.parseSamlRequest = function(samlRequest, options, callback) {
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
            return validateSignature(options.signature, qs.stringify(signedParams), certToPEM(options.signingCert), algorithmSignatures[options.sigAlg]) ?
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

module.exports.validateSignature = validateSignature;

/** 
 * Validates that the signature provided is ok
 * (Used for HTTP-Redirect binding where the signature is sent in query string parameter)
 */ 
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
