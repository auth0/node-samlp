var SignedXml = require('xml-crypto').SignedXml;
var thumbprint = require('@auth0/thumbprint');
var xmlCrypto = require('xml-crypto');
var crypto    = require('crypto');
var encoders  = require('./encoders');
var constants = require('./constants');

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

var DEFAULT_SIG_ALG = 'rsa-sha256';
var DEFAULT_DIGEST_ALG = 'sha256';

module.exports.getSigAlg = function (options) {
  return algorithms.signature[options.signatureAlgorithm || DEFAULT_SIG_ALG];
};

module.exports.signXml = function (options, xml) {
  var signatureAlgorithm = options.signatureAlgorithm || DEFAULT_SIG_ALG;
  var digestAlgorithm = options.digestAlgorithm || DEFAULT_DIGEST_ALG;
  var sig = new SignedXml(null, {
    signatureAlgorithm: algorithms.signature[signatureAlgorithm]
  });

  sig.addReference(options.reference || constants.ELEMENTS.LOGOUT_REQUEST.SIGNATURE_LOCATION_PATH,
                  ["http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                   "http://www.w3.org/2001/10/xml-exc-c14n#"],
                  algorithms.digest[digestAlgorithm]);

  sig.signingKey = options.key;

  var pem = encoders.removeHeaders(options.cert);
  sig.keyInfoProvider = {
    getKeyInfo: function () {
      return "<X509Data><X509Certificate>" + pem + "</X509Certificate></X509Data>";
    }
  };

  sig.computeSignature(xml, {
    location: {
      reference: "//*[local-name(.)='Issuer']",
      action: 'after'
    }
  });

  return sig.getSignedXml();
};

module.exports.validateXmlEmbeddedSignature = function (xml, options) {
  var calculatedThumbprint = '';
  var signature = xmlCrypto.xpath(xml, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
  if (!signature){
    return ['Signature is missing'];
  }

  if (options.thumprints){
    // Make sure thumprints is an array for the validation 
    options.thumbprints = options.thumbprints instanceof Array ? options.thumbprints : [options.thumbprints];
  }

  var sig = new SignedXml();

  sig.keyInfoProvider = {
    getKeyInfo: function () {
      return "<X509Data></X509Data>";
    },
    getKey: function (keyInfo) {
      //If there's no embedded signing cert, use the configured cert through options
      if(!keyInfo || keyInfo.length===0){
        if(!options.signingCert) throw new Error('options.signingCert must be specified for SAMLResponses with no embedded signing certificate');
        return certToPEM(options.signingCert);
      }

      //If there's an embedded signature and thumprints are provided check that
      if (options.thumbprints && options.thumbprints.length > 0)  {
        var embeddedSignature = keyInfo[0].getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "X509Certificate");
        if (embeddedSignature.length > 0) {
          var base64cer = embeddedSignature[0].firstChild.toString();
          calculatedThumbprint = thumbprint.calculate(base64cer);
          
          // using embedded cert, so options.cert is not used anymore
          delete options.signingCert;
          return certToPEM(base64cer);
        }
      }

      // If there's an embedded signature, but no thumprints are supplied, use options.cert
      // either options.cert or options.thumbprints must be specified so at this point there
      // must be an options.cert
      return certToPEM(options.signingCert);
    }
  };

  var valid;

  try {
    sig.loadSignature(signature);
    valid = sig.checkSignature(xml.toString());
  } catch (e) {
    return [e];
  }

  if (!valid) {
    return sig.validationErrors;
  }

  if (options.cert) {
    return;
  }

  if (options.thumbprints) {
    var valid_thumbprint = options.thumbprints.some(function (thumbprint) {
      return calculatedThumbprint.toUpperCase() === thumbprint.toUpperCase();
    });

    if (!valid_thumbprint) {
      return ['Invalid thumbprint (configured: ' + options.thumbprints.join(', ').toUpperCase() + '. calculated: ' + calculatedThumbprint.toUpperCase() + ')'];
    }

    return;
  }

  return;
};

module.exports.sign = function (options, content) {
  var signatureAlgorithm = options.signatureAlgorithm || DEFAULT_SIG_ALG;
  var signer = crypto.createSign(signatureAlgorithm.toUpperCase());
  signer.update(content);
  return signer.sign(options.key, 'base64');
};

module.exports.isValidContentAndSignature = function (content, signature, options) {
  var verifier = crypto.createVerify(options.signatureAlgorithm.split('#')[1].toUpperCase());
  verifier.update(content);
  return verifier.verify(certToPEM(options.signingCert), signature, 'base64');
};

function certToPEM(cert) {
  if (/-----BEGIN CERTIFICATE-----/.test(cert)) {
    return cert;
  }

  cert = cert.match(/.{1,64}/g).join('\n');
  cert = "-----BEGIN CERTIFICATE-----\n" + cert;
  cert = cert + "\n-----END CERTIFICATE-----\n";
  return cert;
}
