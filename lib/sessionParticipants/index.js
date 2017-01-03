function SessionParticipants (sessions) {
  this._participants = sessions || [];
  this.failed = false;
}

// Return an array of active sessions
// serviceProviderLogoutURL - URL where we'll send the LogoutRequest/LogoutResponse
// serviceProviderId - It's the issuer of the SP
// sessionIndex - Generated on auth
// nameId - sent by the SP on auth
// nameIdFormat - sent by the SP on auth
// cert - public key to validate the validity of the request
SessionParticipants.prototype.getAll = function(cb){ 
  return cb(null, this._participants);
};

SessionParticipants.prototype.remove = function (issuer, cb) {
  var sessions = this._participants;
  if (!sessions || sessions.lengh === 0 || !issuer) { return; }
  
  var sessionIndexToRemove = sessions.findIndex(function (session) {
    return session.serviceProviderId === issuer;
  });

  var removedElement;
  // Remove the session from the array
  if (sessionIndexToRemove > -1) {
    removedElement = sessions.splice(sessionIndexToRemove, 1);
    removedElement = removedElement.lengh > 0 ? removedElement[0] : null;
  }

  if (cb) { return cb(null, sessions, removedElement); }
};

module.exports = SessionParticipants;