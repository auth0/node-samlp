var templates             = require('./templates');
var xpath                 = require('xpath');
var utils                 = require('./utils');
var trim_xml              = require('./trim_xml');
var signers               = require('./signers');
var Store                 = require('./store');
var zlib                  = require('zlib');
var qs                    = require('querystring');

var BINDINGS = {
  HTTP_POST:      'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
  HTTP_REDIRECT:  'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
};

var REQUEST_EMBEDDED_SIGNATURE_PATH = "//*[local-name(.)='LogoutRequest']/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']";

module.exports.logout = function (options) {
  options.getSessions = options.getSessions || function(cb){ return cb(null, []); };
  options.store = options.store || new Store();

  var prepareAndSendLogoutRequest = function(req, res, next){
    return options.getSessions(function(err, sessions){
      if (err) return next(err);
      
      // Finished if there are no more session - finish logout
      if (!sessions || sessions.length === 0) return finalize(req, res, next);

      // Use session to generate SAML Request
      var logoutRequest = templates.logoutrequest({
        ID: utils.generateUniqueID(),
        IssueInstant: utils.getRoundTripDateFormat(),
        Issuer: sessions[0].issuer,
        NameID: { value: sessions[0].nameID },
        SessionIndex: sessions[0].sessionIndex,
        Destination: sessions[0].destination
      });

      // Send logout request
      prepareAndSendToken(req, res, 'SAMLRequest', logoutRequest, options, next);
    });
  };

  var finalize = function(req, res, next){
    options.store.get(function(err, data){
      if (err) return next(err);
      if (!data){
        return res.send(200);
      }

      // Data is the parsedSamlRequest - Reply with this information
      var logoutResponse = templates.logoutresponse({
        id:             '_' + utils.generateUniqueID(),
        instant:        utils.generateInstant(),
        inResponseTo:   data.id,        
        // Inverted on purpose - the destination is the issuer of the LogoutRequest
        destination:    data.issuer,
        // Inverted on purpose - the issuer is the destination of the LogoutRequest       
        issuer:         data.destination,
        // TODO: Check partial logout
        samlStatusCode: 'urn:oasis:names:tc:SAML:2.0:status:Success'
      });

      // Update reference to include signature
      options.reference =  "//*[local-name(.)='LogoutResponse' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:protocol']";

      prepareAndSendToken(req, res, 'SAMLResponse', logoutResponse, options, next);
    });
  };

  var validateSamlResponse = function (req, res, next) {
    var SAMLRequest = req.query.SAMLRequest || req.body.SAMLRequest;

    var validate = function (err, buffer) {
      if (err) return next(err);

      var xml = new DOMParser().parseFromString(buffer.toString());
      var logoutRequestNode = xpath.select("//*[local-name(.)='LogoutRequest']", xml)[0];

      // validate expiration
      if (isTokenExpired(logoutRequestNode)) {
        return next(new Error('LogoutRequest has expired'));
      }

      // validate signature
      try {
        validateSignature(req, 'SAMLRequest', xml, options);
      } catch (e) {
        return next(e);
      }

      // get ID, Issuer, NameID and SessionIndex
      var parsedRequest = {};
      parsedRequest.id = logoutRequestNode && logoutRequestNode.getAttribute('ID');

      var issuerNode = xpath.select("//*[local-name(.)='Issuer']", xml);
      parsedRequest.issuer = issuerNode && issuerNode[0] && issuerNode[0].textContent;

      var nameIdNode = xpath.select("//*[local-name(.)='NameID']", xml);
      parsedRequest.nameId = nameIdNode && nameIdNode[0] && nameIdNode[0].textContent;

      var sessionIndexNode = xpath.select("//*[local-name(.)='SessionIndex']", xml);
      parsedRequest.sessionIndex = sessionIndexNode && sessionIndexNode[0] && sessionIndexNode[0].textContent;

      // validate parameters (NameID and SessionIndex)
      if (!parsedRequest.sessionIndex) { return next(new Error('Missing SessionIndex')); }
      if (!parsedRequest.nameId) { return next(new Error('Missing NameID')); }

      var checkSessionIndex = typeof options.validSessionIndex === 'function';
      var isValidSessionIndex = checkSessionIndex && options.validSessionIndex(parsedRequest);
      if (checkSessionIndex && !isValidSessionIndex) {
        return next(new Error('Invalid SessionIndex/NameID'));
      }

      next();
    };

    if (req.body.SAMLRequest || !options.deflate) {
      // HTTP-POST or HTTP-Redirect without deflate encoding
      return validate(null, new Buffer(SAMLRequest, 'base64'));
    }

    // Default: HTTP-Redirect with deflate encoding
    zlib.inflateRaw(new Buffer(SAMLRequest, 'base64'), validate);
  };

  return function (req, res, next) {
    if (req.query.SAMLRequest || req.body.SAMLRequest) {
      // SP Initated flow - We should store who requested it, so we can reply back
      return module.exports.parseLogoutRequest(req.query.SAMLRequest || req.body.SAMLRequest, function (err, requestData) {
        if (err) { return res.send(500, err); }
        return options.store.store(requestData, function(err){
          if(err) return next(err);
                    
          return prepareAndSendLogoutRequest(req, res, next);          
        });        
      });
    }

    if (req.query.SAMLResponse || req.body.SAMLResponse) {
      // Logout in progress - If more sessions continue, if not finish      
      validateSamlResponse(req, res, function(err){
        if (err) {
          // Mark as partial logout

        }
        
        // remove session
        var sessionIndex = '';
        options.store.removeSession(sessionIndex);

        // Continue with next session
        prepareAndSendLogoutRequest(req, res, next);
      });
    }

    // IDP initated - Start flow - In this case we will show a 200 when complete
    return prepareAndSendLogoutRequest(req, res, next);
  };
};

module.exports.parseLogoutRequest = function (samlRequest, callback) {
  utils.parseSamlRequest(samlRequest, function(err, logoutRequestDom) {
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

function prepareAndSendToken(req, res, type, token, options, cb) {
  var send = function (params) {
    if (options.protocolBinding === BINDINGS.HTTP_POST) {
      // HTTP-POST
      res.set('Content-Type', 'text/html');
      return res.send(templates.form({
        type:         type,
        callback:     options.identityProviderUrl,
        RelayState:   params.RelayState,
        token:        params[type]
      }));
    }

    // HTTP-Redirect
    var samlResponseUrl = utils.appendQueryString(options.identityProviderUrl, params);
    res.redirect(samlResponseUrl);
  };

  var params = {};
  params[type] = null;
  params.RelayState = (req.body && req.body.RelayState) || req.query.RelayState || options.relayState || '';

  // canonical request
  token = trim_xml(token);

  if (options.protocolBinding === BINDINGS.HTTP_POST || !options.deflate) {
    // HTTP-POST or HTTP-Redirect without deflate encoding
    try {
      token = signers.signXml(options, token);
    } catch (err) {
      return cb(err);
    }

    params[type] = new Buffer(token).toString('base64');
    return send(params);
  }
  
  // Default: HTTP-Redirect with deflate encoding (http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf - section 3.4.4.1)
  zlib.deflateRaw(new Buffer(token), function (err, buffer) {
    if (err) return cb(err);

    params[type] = buffer.toString('base64');

    // construct the Signature: a string consisting of the concatenation of the SAMLResponse,
    // RelayState (if present) and SigAlg query string parameters (each one URLencoded)
    if (params.RelayState === '') {
      // if there is no RelayState value, the parameter should be omitted from the signature computation
      delete params.RelayState;
    }

    params.SigAlg = signers.getSigAlg(options);
    params.Signature = signers.sign(options, qs.stringify(params));

    send(params);
  });
}

function isTokenExpired (logoutNode) {
  var notOnOrAfterText = logoutNode.getAttribute('NotOnOrAfter');
  if (notOnOrAfterText) {
    var notOnOrAfter = new Date(notOnOrAfterText);
    notOnOrAfter = notOnOrAfter.setMinutes(notOnOrAfter.getMinutes() + 10); // 10 minutes clock skew
    var now = new Date();
    return now > notOnOrAfter;
  }

  return false;
}

function validateSignature (req, type, xml, options) {
  var isRequestSigned = req.body[type] ?
    xpath.select(REQUEST_EMBEDDED_SIGNATURE_PATH, xml).length > 0 : !!req.query.SigAlg;

  if (isRequestSigned) {
    if (req.body[type] || !options.deflate) {
      // HTTP-POST or HTTP-Redirect without deflate encoding
      var validationErrors = signers.validateXmlEmbeddedSignature(xml, options);
      if (validationErrors && validationErrors.length > 0) {
        throw new Error(validationErrors.join('; '));
      }
    }
    else {
      // HTTP-Redirect with deflate encoding
      var signedContent = {};
      signedContent[type] = req.query[type];
      signedContent.RelayState = req.query.RelayState;
      signedContent.SigAlg = req.query.SigAlg;

      if (!signedContent.RelayState) {
        delete signedContent.RelayState;
      }

      if (!signedContent.SigAlg) {
        throw new Error('SigAlg parameter is mandatory');
      }

      var valid = signers.isValidContentAndSignature(qs.stringify(signedContent), req.query.Signature, {
        identityProviderSigningCert: options.identityProviderSigningCert,
        signatureAlgorithm: req.query.SigAlg
      });
      
      if (!valid) {
        throw new Error('invalid signature: the signature value ' + req.query.Signature + ' is incorrect');
      }
    }
  } else if (type === 'SAMLRequest') {
    throw new Error('LogoutRequest message MUST be signed when using an asynchronous binding (POST or Redirect)');
  }
}