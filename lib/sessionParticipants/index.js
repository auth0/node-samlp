function SessionParticipants (sessions) {
  this._participants = sessions || [];
}

function matchingIndex(issuer, sessionIndex, nameId){
  return function(session){
    // If we had the issuer in session and it is provided, they should match
    if (session.serviceProviderId && issuer){
      if (session.serviceProviderId !== issuer) { return false; }
    }

    const hasMatchingSessionIndex = Array.isArray(sessionIndex)
      ? sessionIndex.some((si) => si === session.sessionIndex)
      : sessionIndex === session.sessionIndex;

    // SessionIndex and NameID should match
    return hasMatchingSessionIndex && session.nameId === nameId;
  }
}

/**
 * Retrieves a Session Participant object based on the issuer
 * of a SAMLRequest/SAMLResponse. The 'issuer' should be
 * used to find the correct Session Participant object which
 * represents the issuer of the previous mentions request/response.
 * 
 * @issuer {string} The string as it was received in the SAML request/response
 * @sessionIndices {string[]} An array of strings representing the SessionIndex
 * values as received in the SAML request/response. Only available in LogoutRequests.
 * @nameId {string} The value of the nameId element from the SAML request/response
 * @cb {function} The callback that will be called with '(err, sessionParticipant)'
 */
SessionParticipants.prototype.get = function(issuer, sessionIndices, nameId, cb) {
  // SessionIndex should be mandatory, but not issuer
  // Let's keep using issuer only if available
  const sessionParticipant = this._participants.find(matchingIndex(issuer, sessionIndices, nameId));
  
  if (cb) { return cb(null, sessionParticipant); }
};

/**
 * This method should return 'true' if there are still Session Participant
 * Objects left on the data structure. 'false' otherwise.
 */
SessionParticipants.prototype.hasElements = function() {
  return this._participants.length > 0;
};

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
};

/**
 * Remove a Session Participant from the data structure.
 * 
 * @serviceProviderId {string} The serviceProviderId value of the session participant
 * @sessionIndex {string} The sessionIndex of the session participant
 * @nameId {string} The nameId of the session participant
 * @cb {function} The callback that will be called with '(err, removedElement)'
 */
SessionParticipants.prototype.remove = function(serviceProviderId, sessionIndex, nameId, cb) {
  const sessions = this._participants;
  if (!sessions || sessions.length === 0 || !serviceProviderId) { return cb(); }

  const sessionIndexToRemove = sessions.findIndex(matchingIndex(serviceProviderId, sessionIndex, nameId));

  let removedElement;
  // Remove the session from the array
  if (sessionIndexToRemove > -1) {
    removedElement = sessions.splice(sessionIndexToRemove, 1);
    removedElement = removedElement.length > 0 ? removedElement[0] : null;
  }

  if (cb) { return cb(null, removedElement); }
};

module.exports = SessionParticipants;
