var templates             = require('./templates');
var xpath                 = require('xpath');
var DOMParser             = require('xmldom').DOMParser;
var utils                 = require('./utils');
var trim_xml              = require('./trim_xml');
var signers               = require('./signers');
var SessionStore          = require('./store/session_store');
var SessionParticipants   = require('./sessionParticipants');
var zlib                  = require('zlib');
var qs                    = require('querystring');
var xtend                 = require('xtend');
var constants             = require('./constants');

var BINDINGS  = constants.BINDINGS;
var STATUS = constants.STATUS;

// Analyze if we should merge session handler and store
module.exports.logout = function (options) {
  options.sessionParticipants = options.sessionParticipants || new SessionParticipants();
  options.clearIdPSession = options.clearIdPSession || function (cb){ return cb(); };
  options.store = options.store || new SessionStore(options);

  function prepareAndSendLogoutRequest(sessions, req, res, next) {
    // Finished if there are no more session - finish logout
    if (!sessions || sessions.length === 0) { return finalize(req, res, next); }

    options.store.storeState(req, function (err, state) {
      if (err) return next(err);

      // Use session to generate SAML Request
      var logoutRequest = templates.logoutrequest({
        ID: utils.generateUniqueID(),
        IssueInstant: utils.getRoundTripDateFormat(),
        Issuer: options.issuer, // IdP identifier
        NameID: { value: sessions[0].nameId, Format: sessions[0].nameIdFormat },
        SessionIndex: sessions[0].sessionIndex,
        Destination: sessions[0].serviceProviderLogoutURL
      });

      options.destination = sessions[0].serviceProviderLogoutURL;
      options.relayState = state;
      // Send logout request
      prepareAndSendToken(req, res, 'LOGOUT_REQUEST', logoutRequest, options, next);
    });
  }

  function finalize (req, res, next) {
    options.store.getData(req, constants.STORE_KEYS.SP_INIT, function (err, spData) {
      if (err) return next(err);

      var isPartialLogout = options.store.isLogoutFailed(req);

      options.clearIdPSession(function (err) {
        // If there was an issue cleaning the session, reply with partial logout
        if (err) isPartialLogout = true;

        // No data - It was an IdP initated flow
        if (!spData){
          return res.send(200);
        }

        var data = spData.parsedRequest;
        // Data is the parsedSamlRequest - Reply with this information
        var logoutResponse = templates.logoutresponse({
          id:             '_' + utils.generateUniqueID(),
          instant:        utils.generateInstant(),
          inResponseTo:   data.id,
          // TODO: Review if we can remove the options.destination
          destination:    data.serviceProviderLogoutURL || options.destination, // Destination taken from session (match issuer from the LogoutRequest with session serviceProviderId)
          issuer:         options.issuer, // IdP is the Issuer for this LogoutResponse
          samlStatusCode: isPartialLogout ? STATUS.PARTIAL_LOGOUT : STATUS.SUCCESS
        });

        // Update reference to include signature
        options.reference =  constants.ELEMENTS.LOGOUT_RESPONSE.SIGNATURE_LOCATION_PATH;
        options.destination = data.serviceProviderLogoutURL || options.destination;
        // We stored the relay state of the initial request
        options.relayState = spData.relayState;
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
      var sessionParticipants = getSession(sessions, parsedResponse.issuer);
      
      // validate signature
      try {
        var validationOptions = xtend({signingCert: sessionParticipants.cert}, options);
        utils.validateSignature(req, 'RESPONSE', xml, validationOptions);
      } catch (e) {
        return cb(e);
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
      options.sessionParticipants.getAll(function (err, sessions) {
        if (err) { return next(err); }

        // SP Initated flow.
        if (req.query.SAMLRequest || req.body.SAMLRequest) {
          var opts = {
            getCredentials: function getCredentials(issuer) {
              var session = getSession(sessions, issuer);
              if (!session.cert) return;

              return {
                cert: session.cert,
                thumbprint: session.thumbprint
              };
            }
          };

          parseIncomingLogoutRequest(req, req.query.SAMLRequest || req.body.SAMLRequest, opts, function (err, requestData) {
            if (err) { return next(err); }
            if (!requestData.issuer) {
              return next(new Error('SAML Request with no issuer. Issuer is a mandatory element.'));
            }

            var session = getSession(sessions, requestData.issuer);
            requestData.serviceProviderLogoutURL = session.serviceProviderLogoutURL;

            // We should store who requested the logout, so we can reply back with LogoutResponse
            var spData = {
              parsedRequest: requestData,
              relayState: req.query.RelayState || (req.body && req.body.RelayState)
            };

            options.store.storeData(req, constants.STORE_KEYS.SP_INIT, spData, function (err) {
              if (err) { return next(err); }

              // We remove the session from the LogoutRequest Originator.
              // This session is already saved in the store.
              // We should not send a LogoutRequest to that session
              // Only a LogoutResponse when there are no other session participants active
              options.sessionParticipants.remove(requestData.issuer, function (err) {
                if(err) return next(err);
        
                prepareAndSendLogoutRequest(sessions, req, res, next);
              });
            });
          });

        // Logout flow in progress, incoming SAMLResponse from SP. (Could be SP initiated or IdP initiated)
        } else if (req.query.SAMLResponse || req.body.SAMLResponse) {
          // Verify that the state sent to the SP matches the one returned
          options.store.verifyState(req, req.query.RelayState || (req.body && req.body.RelayState), function (err, ok, state) {
            if (err) { return next(err); }
            if (!ok) { return next(state); }
            // If there are sessions left, keep sending LogoutRequest to Session Participants. If not finish
            validateSamlResponse(req, sessions, function (err, logoutResponse) {
              if (err) { return next(err); }

              // Mark global status as partial logout if a logout does not succeed
              if (logoutResponse.status !== STATUS.SUCCESS) { options.store.setLogoutStatusFailed(req); }

              // LogoutResponse was OK, we remove the session participant from the IdP
              options.sessionParticipants.remove(logoutResponse.issuer, function (err) {
                if(err) return next(err);

                // Continue with next session if any
                prepareAndSendLogoutRequest(sessions, req, res, next);
              });
            });
          });

        // IdP initated - Start flow - In this case we will show a 200 when complete
        } else {
          prepareAndSendLogoutRequest(sessions, req, res, next);
        }
      });
    } catch (e) {
      return next(e);
    }
  };
};

/**
 * Gets the current session assosiated by a Issuer
 */
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
  params.RelayState = options.relayState || '';

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