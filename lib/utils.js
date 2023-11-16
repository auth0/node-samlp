const zlib                  = require('zlib');
const xmldom                = require('@auth0/xmldom');
const qs                    = require('querystring');
const xpath                 = require('xpath');
const url                   = require('url');
const xtend                 = require('xtend');
const signers               = require('./signers');
const constants             = require('./constants');
const IdGenerator           = require('auth0-id-generator');

const generator = new IdGenerator({len: 20, alphabet:"abcdef0123456789"});

const algorithmSignatures = {
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': 'rsa-sha256',
  'http://www.w3.org/2000/09/xmldsig#rsa-sha1': 'rsa-sha1'
};

module.exports.parseSamlRequest = function(req, samlRequest, type, options, callback) {
  function checkSignature(xml, cb) {
    const opts = {
      signingCert: options.signingCert,
      thumbprints: options.thumbprints,
      deflate: !!req.query.Signature,
      relayState: options.relayState
    };

    try {
      validateSignature(req, type, xml, opts);
      return cb(null, xml);
    } catch (e) {
      return cb(e);
    }
  }

  /**
   * Check if the issuer signing credentials are set correctly.
   * If they aren't and the IdP passed a `getCredentials` function
   * will use it to configure the issuer credentials to be used when
   * validating the incoming SAML Request
   * @xml {Object}   The SAML Request as a DOM Object
   * @cb  {Function} The callback. Will return a boolean if the SAML Request has to get its signature verified
   */
  function configureSigningCredentials(xml, cb) {
    if (options.signingCert || options.thumprints) { return cb(null, true); }

    if (!options.getCredentials) {
      return cb(null, false);
    }

    let issuer, sessionIndices, nameId;
    const issuerNode = xpath.select(constants.ELEMENTS[type].ISSUER_PATH, xml);

    if (issuerNode && issuerNode.length > 0) {
      issuer = issuerNode[0].textContent;
    }

    // If LogoutRequest, we should check sessionIndex too
    if (constants.ELEMENTS[type].SESSION_INDEX_PATH){
      const sessionIndexNodes = xpath.select(constants.ELEMENTS[type].SESSION_INDEX_PATH, xml);
      if (sessionIndexNodes && sessionIndexNodes.length > 0) {
        sessionIndices = sessionIndexNodes.map((si) => si.textContent);
      }
    }

    // If LogoutRequest, we should check sessionIndex too
    if (constants.ELEMENTS[type].NAME_ID){
      const nameIdNode = xpath.select(constants.ELEMENTS[type].NAME_ID, xml);
      if (nameIdNode && nameIdNode.length > 0) {
        nameId = nameIdNode[0].textContent;
      }
    }

    if (!issuer && !(sessionIndices && sessionIndices.length) && !nameId){
      return cb(null, false);
    }

    options.getCredentials(issuer, sessionIndices, nameId, function (err, credentials) {
      if (!credentials){
        return cb(null, false);
      }

      options.signingCert = credentials.cert;
      options.thumbprints = credentials.thumbprints;
      return cb(null, true);
    });
  }

  if (!samlRequest) return callback();

  try {
    const input = new Buffer(samlRequest, 'base64');

    if (input[0] === 60) {  // open tag
      // content is just encoded, not zipped
      const xml = new xmldom.DOMParser().parseFromString(input.toString());
      if (!xml || !xml.documentElement) {
        return callback(new Error('Invalid SAML Request'));
      }

      configureSigningCredentials(xml, function (err, shouldValidate) {
        if (!shouldValidate) {
          return callback(null, xml);
        }
        checkSignature(xml, callback);
      });

    } else {
      zlib.inflateRaw(input, function(err, buffer) {
        if (err) { return callback(err); }

        let xml = null;
      try{
         xml = new xmldom.DOMParser().parseFromString(buffer.toString());
      }
      catch(e) {
        return callback(new Error(e));
      }

        if (!xml || !xml.documentElement) {
          return callback(new Error('Invalid SAML Request'));
        }

        configureSigningCredentials(xml, function (err, shouldValidate) {
          if (!shouldValidate) {
            return callback(null, xml);
          }
          checkSignature(xml, callback);
        });
      });
    }
  } catch(e) {
    callback(e);
  }
};

/**
 * Generates a random alphanumeric ID.
 * > IDs are 20 characters long and use the hexadecimal alphabet
 * @returns {string}
 */
module.exports.generateUniqueID = function() {
  return generator.get();
};

/**
 * @return {string} the current date/time in `xs:DateTime` format, with millisecond precision.
 */
module.exports.generateInstant = function(){
  return module.exports.formatXmlDateTime(new Date());
};

/**
 * Formats the given date in `xs:DateTime` format as per Core SAML "1.3.3 Time Values".
 *
 * > All SAML time values have the type xs:dateTime, which is built in to the W3C XML Schema Datatypes
 * > specification [Schema2], and MUST be expressed in UTC form, with no time zone component.
 * > SAML system entities SHOULD NOT rely on time resolution finer than milliseconds. Implementations
 * > MUST NOT generate time instants that specify leap seconds.
 *
 * @see https://www.w3.org/TR/xmlschema-2/#dateTime
 * @see https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
 *
 * @param {Date} date the date to format
 * @return {string} the formated date/time in `xs:DateTime` format, with millisecond precision.
 */
module.exports.formatXmlDateTime = function (date) {
  return date.getUTCFullYear() + '-' +
    ('0' + (date.getUTCMonth() + 1)).slice(-2) + '-' +
    ('0' + date.getUTCDate()).slice(-2) + 'T' +
    ('0' + date.getUTCHours()).slice(-2) + ":" +
    ('0' + date.getUTCMinutes()).slice(-2) + ":" +
    ('0' + date.getUTCSeconds()).slice(-2) + "." +
    ('00' + date.getUTCMilliseconds()).slice(-3) + "Z";
};

module.exports.appendQueryString = function(initialUrl, query) {
  const parsed = url.parse(initialUrl, true);
  parsed.query = xtend(parsed.query, query);
  delete parsed.search;
  return url.format(parsed);
};

module.exports.validateSignature = validateSignature;

function validateSignature(req, element_type, xml, options) {
  const type = constants.ELEMENTS[element_type].PROP;

  const isPostOrWithoutDeflate = (req.body && req.body[type]) || !options.deflate;
  const isRequestSigned = isPostOrWithoutDeflate ?
    xpath.select(options.signaturePath || constants.ELEMENTS[element_type].SIGNATURE_VALIDATION_PATH, xml).length > 0 : !!req.query.Signature;

  if (isRequestSigned) {
    if (isPostOrWithoutDeflate) {
      // HTTP-POST or HTTP-Redirect without deflate encoding
      const validationErrors = signers.validateXmlEmbeddedSignature(xml, options);
      if (validationErrors && validationErrors.length > 0) {
        throw new Error('Signature check errors: ' + validationErrors.join('; '));
      }
    }
    else {
      // HTTP-Redirect with deflate encoding
      let signedContent = {};
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

      const valid = signers.isValidContentAndSignature(qs.stringify(signedContent), req.query.Signature, {
        signingCert: options.signingCert,
        signatureAlgorithm: req.query.SigAlg
      });

      if (!valid) {
        throw new Error('Signature check errors: The signature provided (' + req.query.Signature + ') does not match the one calculated');
      }
    }
  } else if (options.signingCert) {
    throw new Error(type + ' message MUST be signed when using an asynchronous binding (POST or Redirect)');
  }
}
