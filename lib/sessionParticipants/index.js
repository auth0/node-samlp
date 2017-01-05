function SessionParticipants (sessions) {
  this._participants = sessions || [];
}

/**
 * Retrieves a Session Participant object based on the issuer
 * of a SAMLRequest/SAMLResponse. The 'issuer' should be
 * used to find the correct Session Participant object which
 * represents the issuer of the previous mentions request/response.
 * 
 * @issuer {string}   The string as it was received in the SAML request/response
 * @cb     {function} The callback that will be called with '(err, sessionParticipant)'
 */
SessionParticipants.prototype.get = function(issuer, cb) {
  var s = this._participants.find(function (session) {
    return session.serviceProviderId === issuer;
  });

  if (cb) { return cb(null, s); }
}

/**
 * This method should return 'true' if there are still Session Participant
 * Objects left on the data structure. 'false' otherwise.
 */
SessionParticipants.prototype.hasElements = function() {
  return this._participants.length > 0;
}

/**
 * Get the first Session Participant object from the data structure.
 * This method should not remove the object from the data structure.
 * If no elements are left, should return 'undefined'
 * 
 * @cb     {function} The callback that will be called with '(err, sessionParticipant)'
 */
SessionParticipants.prototype.getFirst = function(cb) {
  var next;
  if (this.hasElements()) {
    next = this._participants[0];
  }

  return cb(null, next);
}

/**
 * Remove a Session Participant from the data structure.
 * 
 * @issuer {string}   The string as it was received in the SAML request/response
 * @cb     {function} The callback that will be called with '(err, removedElement)'
 */
SessionParticipants.prototype.remove = function(issuer, cb) {
  var sessions = this._participants;
  if (!sessions || sessions.length === 0 || !issuer) { return cb(); }
  
  var sessionIndexToRemove = sessions.findIndex(function (session) {
    return session.serviceProviderId === issuer;
  });

  var removedElement;
  // Remove the session from the array
  if (sessionIndexToRemove > -1) {
    removedElement = sessions.splice(sessionIndexToRemove, 1);
    removedElement = removedElement.length > 0 ? removedElement[0] : null;
  }

  if (cb) { return cb(null, removedElement); }
};

module.exports = SessionParticipants;