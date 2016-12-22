function SessionHandler(){
  this.failed = false;
}

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