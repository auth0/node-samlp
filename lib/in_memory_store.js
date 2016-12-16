function Store() {
}

Store.prototype.store = function(data, cb) {
  this.request = data;
  if (cb) { cb(); }
};

Store.prototype.get = function(cb) {
  cb(null, this.request);
};

Store.prototype.clear = function(cb) {
  this.request = null;
  if (cb) { cb(); }
};

module.exports = Store;