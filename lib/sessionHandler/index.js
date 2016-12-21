function SessionHandler(){

}

SessionHandler.prototype.getActiveSessions = function(cb){ 
  return cb(null, []); 
};

SessionHandler.prototype.clearIdPSession = function(cb) { 
  return cb(); 
};

module.exports = SessionHandler;