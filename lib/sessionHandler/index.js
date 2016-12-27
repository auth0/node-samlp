function SessionHandler(){
  this.failed = false;
}

// Return an array of active sessions
// serviceProviderLogoutURL - URL where we'll send the LogoutRequest/LogoutResponse
// serviceProviderId - It's the issuer of the SP
// sessionIndex - Generated on auth
// nameId - sent by the SP on auth
// nameIdFormat - sent by the SP on auth
// cert - public key to validate the validity of the request
SessionHandler.prototype.getActiveSessions = function(cb){ 
  return cb(null, []); 
};

SessionHandler.prototype.clearIdPSession = function(cb) { 
  return cb(); 
};

SessionHandler.prototype.setLogoutStatusFailed = function(){
  this.failed = true;
};

SessionHandler.prototype.isLogoutFailed = function(){
  return this.failed;
};

module.exports = SessionHandler;