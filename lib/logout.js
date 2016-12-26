var templates             = require('./templates');
var xpath                 = require('xpath');
var DOMParser             = require('xmldom').DOMParser;
var utils                 = require('./utils');
var trim_xml              = require('./trim_xml');
var signers               = require('./signers');
var InMemoryStore         = require('./store/in_memory_store');
var SessionHandler        = require('./sessionHandler');
var zlib                  = require('zlib');
var qs                    = require('querystring');
var util                  = require('util');
var xtend                 = require('xtend');
var constants             = require('./constants');

var BINDINGS  = constants.BINDINGS;
var STATUS = constants.STATUS;

// Analyze if we should merge session handler and store
module.exports.logout = function (options) {
  options.sessionHandler = options.sessionHandler || new SessionHandler();
  options.store = options.store || new InMemoryStore();

  function prepareAndSendLogoutRequest(sessions, req, res, next) {
    // Finished if there are no more session - finish logout
    if (!sessions || sessions.length === 0) { return finalize(req, res, next); }

    // TODO: We need to check if we already sent the logoutRequest to sessions[0]
    // Use session to generate SAML Request
    var logoutRequest = templates.logoutrequest({
      ID: utils.generateUniqueID(),
      IssueInstant: utils.getRoundTripDateFormat(),
      Issuer: options.issuer, // IdP identifier
      NameID: { value: sessions[0].nameID },
      SessionIndex: sessions[0].sessionIndex,
      Destination: sessions[0].serviceProviderLogoutURL
    });

    options.destination = sessions[0].serviceProviderLogoutURL;
    // Send logout request
    prepareAndSendToken(req, res, 'LOGOUT_REQUEST', logoutRequest, options, next);
  }

  function finalize (req, res, next) {
    options.sessionHandler.clearIdPSession(function (err) {
      // If there was an issue cleaning the session, reply with partial logout
      if (err) options.sessionHandler.setLogoutStatusFailed();

      options.store.get(function (err, data) {
        if (err) return next(err);
        
        if (!data){
          return res.send(200);
        }

        // Data is the parsedSamlRequest - Reply with this information
        var logoutResponse = templates.logoutresponse({
          id:             '_' + utils.generateUniqueID(),
          instant:        utils.generateInstant(),
          inResponseTo:   data.id,     
          // TODO: Review if we can remove the options.destination
          destination:    data.serviceProviderLogoutURL || options.destination, // Destination taken from session (match issuer from the LogoutRequest with session serviceProviderId)
          issuer:         options.issuer, // IdP is the Issuer for this LogoutResponse
          // TODO: Maybe we can use the store
          samlStatusCode: options.sessionHandler.isLogoutFailed() ? STATUS.PARTIAL_LOGOUT : STATUS.SUCCESS
        });

        // Update reference to include signature
        options.reference =  constants.ELEMENTS.LOGOUT_RESPONSE.SIGNATURE_LOCATION_PATH;
        options.destination = data.serviceProviderLogoutURL || options.destination;

        prepareAndSendToken(req, res, 'LOGOUT_RESPONSE', logoutResponse, options, next);
      });
    });
  }

  function validateSamlResponse(req, sessions, cb) {
    var SAMLResponse = req.query.SAMLResponse || req.body.SAMLResponse;

    function parseAndValidate(err, buffer) {
      if (err) { return cb(err); }
      var xml = new DOMParser().parseFromString(buffer.toString());
      var parsedResponse = {};

      // status code
      var statusCodes = xml.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol', 'StatusCode');
      var statusCodeXml = statusCodes[0];
      if (statusCodeXml) {
        parsedResponse.status = statusCodeXml.getAttribute('Value');

        // status sub code
        var statusSubCodeXml = statusCodes[1];
        if (statusSubCodeXml) {
          parsedResponse.subCode = statusSubCodeXml.getAttribute('Value');
        }
      }

      // status message
      var samlStatusMsgXml = xml.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol', 'StatusMessage')[0];
      if (samlStatusMsgXml) {
        parsedResponse.message = samlStatusMsgXml.textContent;
      }

      // status detail
      var samlStatusDetailXml = xml.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol', 'StatusDetail')[0];
      if (samlStatusDetailXml) {
        parsedResponse.detail = samlStatusDetailXml.textContent;
      }
      // Issuer
      var issuer = xml.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Issuer')[0];
      if (issuer) {
        parsedResponse.issuer = issuer.textContent;
      }

      req.parsedSAMLResponse = parsedResponse;
      var sessionParticipant = getSession(sessions, parsedResponse.issuer);
      // validate signature
      try {
        var validationOptions = xtend({signingCert: sessionParticipant.cert}, options);
        utils.validateSignature(req, 'RESPONSE', xml, validationOptions);
      } catch (e) {
        return cb(e);
      }

      // validate status
      if (parsedResponse.status !== STATUS.SUCCESS) {
        var err_message = parsedResponse.message && parsedResponse.detail ?
          util.format('%s (%s)', parsedResponse.message, parsedResponse.detail) :
          parsedResponse.message ||
          parsedResponse.detail ||
          util.format('unexpected SAMLP Logout response (%s)', parsedResponse.status);

        // Include the response as on failed logouts, we want to continue with the other sessions
        return cb(new Error(err_message), parsedResponse);
      }

      cb(null, parsedResponse);
    }

    if (req.body.SAMLResponse || !options.deflate) {
      // HTTP-POST or HTTP-Redirect without deflate encoding
      return parseAndValidate(null, new Buffer(SAMLResponse, 'base64'));
    }

    // Default: HTTP-Redirect with deflate encoding
    zlib.inflateRaw(new Buffer(SAMLResponse, 'base64'), parseAndValidate);
  }

  return function (req, res, next) {
    try {
      // Get SP Active Sessions
      options.sessionHandler.getActiveSessions(function (err, sessions) {
        if (err) { return next(err); }

        // SP Initated flow. Scenario 1 Step 1
        if (req.query.SAMLRequest || req.body.SAMLRequest) {
          var opts = {
            getCredentials: function getCredentials(issuer) {
              var session = getSession(sessions, issuer);
              return {
                cert: session.cert
                //TODO thumbprints ?
              }
            }
          };
          parseIncomingLogoutRequest(req, req.query.SAMLRequest || req.body.SAMLRequest, opts, function (err, requestData) {
            if (err) { return next(err); }

            // TODO: What if issuer is undefined
            var session = getSession(sessions, requestData.issuer);
            requestData.serviceProviderLogoutURL = session.serviceProviderLogoutURL;

            // We should store who requested the logout, so we can reply back with LogoutResponse
            options.store.store(requestData, function (err) {
              if (err) { return next(err); }

              // We remove the session from the LogoutRequest Originator.
              // This session is already saved in the store.
              // We should not send a LogoutRequest to that session
              // Only a LogoutResponse when there are no other session participants active
              removeSession(sessions, requestData);
      
              prepareAndSendLogoutRequest(sessions, req, res, next);
            });
          });

        // SP Initiated flow in progress, incoming SAMLResponse from SP. Scenario 1 Step 2
        } else if (req.query.SAMLResponse || req.body.SAMLResponse) {
          // If there are sessions left, keep sending LogoutRequest to Session Participants. If not finish
          validateSamlResponse(req, sessions, function (err, logoutResponse) {
            if (err) {
              // Mark global status as partial
              options.sessionHandler.setLogoutStatusFailed();
            }

            // LogoutResponse was OK, we remove the session participant
            removeSession(sessions, logoutResponse);

            // Continue with next session if any
            prepareAndSendLogoutRequest(sessions, req, res, next);
          });

        // IDP initated - Start flow - In this case we will show a 200 when complete
        } else {
          prepareAndSendLogoutRequest(sessions, req, res, next);
        }
      });
    } catch (e) {
      return next(e);
    }
  };
};

// TODO: Check if issuer is mandatory, maybe we should check by SessionIndex
function getSession(sessions, issuer) {
  if (!issuer) {
    return {};
  }

  var session = sessions.find(function (s) {
    return s.serviceProviderId === issuer;
  });

  return session || {};
}

/**
 * Removes the Session Participant that corresponds
 * to the LogoutResponse.
 * This function Modifies the sessions array received
 */
function removeSession(sessions, logoutResponse) {
  if (!sessions || sessions.lengh === 0) { return; }
  
  var sessionIndexToRemove = sessions.findIndex(function (session) {
    return session.serviceProviderId === logoutResponse.issuer;
  });

  // Remove the session from the array
  if (sessionIndexToRemove > -1) {
    sessions.splice(sessionIndexToRemove, 1);
  }
}

/**
 * Parse the SP initiated Logout Request.
 * This Logout Request is incoming from the SAML SP into the SAML IdP.
 * @returns {Object} The Logout Request data as a JSON Object
 */
function parseIncomingLogoutRequest(req, samlRequest, options, callback) {
  var type = "LOGOUT_REQUEST";
  utils.parseSamlRequest(req, samlRequest, type, options, function (err, logoutRequestDom) {
    if (err) { return callback(err); }

    var data = {};
    var issuer = xpath.select(constants.ELEMENTS[type].ISSUER_PATH, logoutRequestDom);
    if (issuer && issuer.length > 0) { data.issuer = issuer[0].textContent; }

    var sessionIndex = xpath.select("//*[local-name(.)='SessionIndex']/text()", logoutRequestDom);
    if (sessionIndex && sessionIndex.length > 0) { data.sessionIndex = sessionIndex[0].textContent; }

    var nameId = xpath.select("//*[local-name(.)='NameID']", logoutRequestDom);
    if (nameId && nameId.length > 0) {
      data.nameId = nameId[0].textContent;
      data.nameIdFormat = nameId[0].getAttribute('Format');
    }

    var destination = logoutRequestDom.documentElement.getAttribute('Destination');
    if (destination) data.destination = destination;

    var id = logoutRequestDom.documentElement.getAttribute('ID');
    if (id) data.id = id;

    var signature = xpath.select(options.signaturePath || constants.ELEMENTS[type].SIGNATURE_VALIDATION_PATH, logoutRequestDom);
    if (signature && signature.length > 0) { data.signature = signature[0].textContent; }

    callback(null, data);
  });
}

function prepareAndSendToken(req, res, element_type, token, options, cb) {
  var type = constants.ELEMENTS[element_type].PROP;

  var send = function (params) {
    if (options.protocolBinding !== BINDINGS.HTTP_REDIRECT) {
      // HTTP-POST
      res.set('Content-Type', 'text/html');
      return res.send(templates.form({
        type:         type,
        callback:     options.destination,
        RelayState:   params.RelayState,
        token:        params[type]
      }));
    }

    // HTTP-Redirect
    var samlResponseUrl = utils.appendQueryString(options.destination, params);
    res.redirect(samlResponseUrl);
  };

  var params = {};
  params[type] = null;
  params.RelayState = (req.body && req.body.RelayState) || req.query.RelayState || options.relayState || '';

  // canonical request
  token = trim_xml(token);

  if (options.protocolBinding !== BINDINGS.HTTP_REDIRECT || !options.deflate) {
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