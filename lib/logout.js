var templates             = require('./templates');
var xpath                 = require('xpath');
var DOMParser             = require('@auth0/xmldom').DOMParser;
var utils                 = require('./utils');
var trim_xml              = require('./trim_xml');
var signers               = require('./signers');
var SessionStore          = require('flowstate').SessionStore;
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
  options.store = options.store || new SessionStore({ key: '_logoutState'});

  function prepareAndSendLogoutRequest(sessionParticipants, transactionId, req, res, next) {
    // Finished if there are no more session - finish logout
    if (!sessionParticipants.hasElements()) { return finalize(transactionId, req, res, next); }

    sessionParticipants.getFirst(function (err, participant) {
      // Store the sessionIndex in session so when the logout request comes back we can use that to validate
      var logoutRequestState = { transactionId: transactionId, sessionIndex: participant.sessionIndex, issuer: participant.serviceProviderId, nameId: participant.nameId };

      options.store.save(req, logoutRequestState, function (err, relayState) {
        if (err) return next(err);

        // Use session to generate SAML Request
        var logoutRequest = templates.logoutrequest({
          ID: utils.generateUniqueID(),
          IssueInstant: utils.generateInstant(),
          Issuer: options.issuer, // IdP identifier
          NameID: { value: participant.nameId, Format: participant.nameIdFormat },
          SessionIndex: participant.sessionIndex,
          Destination: participant.serviceProviderLogoutURL
        });

        options.destination = participant.serviceProviderLogoutURL;
        options.relayState = relayState;
        options.participantBinding = participant.binding;
        // Send logout request
        prepareAndSendToken(req, res, 'LOGOUT_REQUEST', logoutRequest, options, next);
      });
    });
  }

  function finalize(transactionId, req, res, next) {
    options.store.load(req, transactionId, {destroy: true}, function (err, transaction) {
      if (err) { return next(err); }

      var isPartialLogout = transaction && transaction.global_status === 'failed';

      options.clearIdPSession(function (err) {
        // If there was an issue cleaning the session, reply with partial logout
        if (err) { isPartialLogout = true; }

        // No data - It was an IdP initated flow
        if (!transaction || !transaction.parsedRequest){
          return res.send(200);
        }

        var data = transaction.parsedRequest;
        // Data is the parsedSamlRequest - Reply with this information
        var logoutResponse = templates.logoutresponse({
          id:             '_' + utils.generateUniqueID(),
          instant:        utils.generateInstant(),
          inResponseTo:   data.id,
          destination:    data.serviceProviderLogoutURL || options.destination, // Destination taken from session (matches issuer from the LogoutRequest with session serviceProviderId)
          issuer:         options.issuer, // IdP is the Issuer for this LogoutResponse
          samlStatusCode: isPartialLogout ? STATUS.PARTIAL_LOGOUT : STATUS.SUCCESS,
          samlStatusMessage: options.samlStatusMessage,
        });

        // Update reference to include signature
        options.reference =  constants.ELEMENTS.LOGOUT_RESPONSE.SIGNATURE_LOCATION_PATH;
        options.destination = data.serviceProviderLogoutURL || options.destination;
        // We stored the relay state of the initial request
        options.relayState = transaction.relayState;
        options.participantBinding = transaction.binding;
        prepareAndSendToken(req, res, 'LOGOUT_RESPONSE', logoutResponse, options, next);
      });
    });
  }

  function validateSamlResponse(req, sessionParticipant, cb) {
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
      if (!sessionParticipant.cert) {
        // If there's no certificate to check the signature, let it pass
        return cb(null, parsedResponse);
      }

      // validate signature
      try {
        var validationOptions = xtend({signingCert: sessionParticipant.cert}, options);
        utils.validateSignature(req, 'LOGOUT_RESPONSE', xml, validationOptions);
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
      // SP Initated flow.
      if (req.query.SAMLRequest || req.body.SAMLRequest) {
        const opts = {
          getCredentials: function getCredentials(issuer, sessionIndices, nameId, cb) {
            options.sessionParticipants.get(issuer, sessionIndices, nameId, function (err, session) {
              if (err) { return cb(err); }
              if (!session) { return cb(new Error('Invalid Session Participant')) };
              if (!session.cert) { return cb(); };

              return cb(null, {
                cert: session.cert,
                thumbprint: session.thumbprint
              });
            });
          }
        };
        parseIncomingLogoutRequest(req, req.query.SAMLRequest || req.body.SAMLRequest, opts, function (err, requestData) {
          if (err) { return next(err); }

          if (!requestData.issuer) {
            return next(new Error('SAML Request with no issuer. Issuer is a mandatory element.'));
          }

          options.sessionParticipants.get(requestData.issuer, requestData.sessionIndices, requestData.nameId, function (err, session) {
            if (err) { return next(err); }
            if (!session && !options.destination) { return next(new Error('Invalid Session Participant')); }

            // We should store who requested the logout, so we can reply back with LogoutResponse
            const spData = {
              parsedRequest: {
                id: requestData.id,
                serviceProviderLogoutURL: (session|| {}).serviceProviderLogoutURL || options.destination
              },
              relayState: req.query.RelayState || (req.body && req.body.RelayState),
            };

            if (session && session.binding) {
              // record the client-specific binding, if there is one.
              spData.binding = session.binding;
            }

            options.store.save(req, spData, function (err, transactionId) {
              if (err) { return next(err); }

              // We remove the session from the LogoutRequest Originator.
              // This session is already saved in the store.
              // We should not send a LogoutRequest to that session
              // Only a LogoutResponse when there are no other session participants active
              const { serviceProviderId, sessionIndex, nameId } = session || {};
              options.sessionParticipants.remove(serviceProviderId, sessionIndex, nameId, function (err) {
                if (err) { return next(err); }

                prepareAndSendLogoutRequest(options.sessionParticipants, transactionId, req, res, next);
              });
            });
          });
        });

      // Logout flow in progress, incoming SAMLResponse from SP. (Could be SP initiated or IdP initiated)
      } else if (req.query.SAMLResponse || req.body.SAMLResponse) {
        function process(state, transactionId) {
          // LogoutResponse was OK, we remove the session participant from the IdP
          options.sessionParticipants.remove(state.issuer, state.sessionIndex, state.nameId, function (err) {
            if(err) return next(err);

            // Continue with next session if any
            prepareAndSendLogoutRequest(options.sessionParticipants, transactionId, req, res, next);
          });
        }

        // Verify that the state sent to the SP matches the one returned
        var h = req.query.RelayState || (req.body && req.body.RelayState);
        options.store.load(req, h, {destroy: true}, function (err, state) {
          if (err) { return next(err); }
          if (!state) { return next(new Error('Invalid RelayState')); }

          options.sessionParticipants.get(state.issuer, [state.sessionIndex], state.nameId, function (err, sessionParticipant) {
            if (err) { return next(err); }
            if (!sessionParticipant) { return next(new Error('Invalid Session Participant')) };

            // If there are sessions left, keep sending LogoutRequest to Session Participants. If not finish
            validateSamlResponse(req, sessionParticipant, function (err, logoutResponse) {
              if (err) { return next(err); }
              var transactionId = state.transactionId;
              if (logoutResponse.status === STATUS.SUCCESS) {
                return process(state, transactionId);
              }

              // Mark global status as partial logout if a logout does not succeed
              options.store.load(req, transactionId, function (err, globalState) {
                globalState.global_status = 'failed';
                options.store.update(req, transactionId, globalState, function (err) {
                  if (err) { return next(err); }
                  // TODO: Review - because we need to remove the session that replied, but send the response to the originator
                  process(state, transactionId);
                });
              });
            });
          });
        });

      // IdP initated - Start flow - In this case we will show a 200 when complete
      } else {
        options.store.save(req, {}, function (err, transactionId) {
          prepareAndSendLogoutRequest(options.sessionParticipants, transactionId, req, res, next);
        });
      }
    } catch (e) {
      return next(e);
    }
  };
};

/**
 * Parse the SP initiated Logout Request.
 * This Logout Request is incoming from the SAML SP into the SAML IdP.
 * @returns {Object} The Logout Request data as a JSON Object
 */
function parseIncomingLogoutRequest(req, samlRequest, options, callback) {
  const type = "LOGOUT_REQUEST";
  utils.parseSamlRequest(req, samlRequest, type, options, function (err, logoutRequestDom) {
    if (err) { return callback(err); }

    const data = {};
    const issuer = xpath.select(constants.ELEMENTS[type].ISSUER_PATH, logoutRequestDom);
    if (issuer && issuer.length > 0) { data.issuer = issuer[0].textContent; }

    const sessionIndexNodes = xpath.select("//*[local-name(.)='SessionIndex']/text()", logoutRequestDom);
    if (sessionIndexNodes && sessionIndexNodes.length > 0) { data.sessionIndices = sessionIndexNodes.map((si) => si.textContent); }

    const nameId = xpath.select("//*[local-name(.)='NameID']", logoutRequestDom);
    if (nameId && nameId.length > 0) {
      data.nameId = nameId[0].textContent;
      data.nameIdFormat = nameId[0].getAttribute('Format');
    }

    const destination = logoutRequestDom.documentElement.getAttribute('Destination');
    if (destination) { data.destination = destination; }

    const id = logoutRequestDom.documentElement.getAttribute('ID');
    if (id) data.id = id;

    const signature = xpath.select(options.signaturePath || constants.ELEMENTS[type].SIGNATURE_VALIDATION_PATH, logoutRequestDom);
    if (signature && signature.length > 0) { data.signature = signature[0].textContent; }

    callback(null, data);
  });
}

function prepareAndSendToken(req, res, element_type, token, options, cb) {
  const binding = options.participantBinding || options.protocolBinding;
  var type = constants.ELEMENTS[element_type].PROP;
  
  var send = function (params) {
    if (binding !== BINDINGS.HTTP_REDIRECT) {
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
    try {
      const samlResponseUrl = utils.appendQueryString(options.destination, params);
      res.redirect(samlResponseUrl);
    } catch (e) {
      cb(new Error('The logout URL may be missing or misconfigured'));
    }
  };

  var params = {};
  params[type] = null;
  params.RelayState = options.relayState || '';

  // canonical request
  token = trim_xml(token);

  if (binding !== BINDINGS.HTTP_REDIRECT || !options.deflate) {
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

module.exports.sendLogoutError = function(options){
  return function(req, res, next){
    if (!options.destination) {
      return next(new Error('Destination not specified'));
    }

    var error = options.error || {};

    var logoutResponse = templates.logoutresponse({
      id:             '_' + utils.generateUniqueID(),
      instant:        utils.generateInstant(),
      inResponseTo:   options.inResponseTo,
      destination:    options.destination,
      issuer:         options.issuer,
      samlStatusCode:  error.code || STATUS.RESPONDER,
      samlStatusMessage: error.description
    });

    // Signature location
    options.reference = constants.ELEMENTS.LOGOUT_RESPONSE.SIGNATURE_LOCATION_PATH;
    options.relayState = options.relayState || req.query.RelayState || (req.body || {}).RelayState;

    return prepareAndSendToken(req, res, 'LOGOUT_RESPONSE', logoutResponse, options, next);
  };
};
