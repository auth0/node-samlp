function Store() {
  this.clear();
}

Store.prototype.storeData = function(req, key, data, cb) {
  this._memoryStore[key] = data;
  if (cb) { cb(null, data); }
};

Store.prototype.getData = function(req, key, cb) {
  cb(null, this._memoryStore[key]);
};

Store.prototype.clear = function(cb) {
  this._memoryStore = {};
  if (cb) { cb(); }
};

Store.prototype.setLogoutStatusFailed = function(){
  this.failed = true;
};

Store.prototype.isLogoutFailed = function(){
  return this.failed;
};

Store.prototype.storeState = function(req, callback) {
  callback(null, req.query.RelayState || (req.body && req.body.RelayState));
};

Store.prototype.verifyState = function(req, providedState, callback) {
  callback(null, true);
};


module.exports = Store;