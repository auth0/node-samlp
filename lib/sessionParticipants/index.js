function SessionParticipant(){
  this.failed = false;
}

// Return an array of active sessions
// serviceProviderLogoutURL - URL where we'll send the LogoutRequest/LogoutResponse
// serviceProviderId - It's the issuer of the SP
// sessionIndex - Generated on auth
// nameId - sent by the SP on auth
// nameIdFormat - sent by the SP on auth
// cert - public key to validate the validity of the request
SessionParticipant.prototype.getAll = function(cb){ 
  return cb(null, []); 
};

SessionParticipant.prototype.remove = function(issuer) {
  return;
};

module.exports = SessionParticipant;