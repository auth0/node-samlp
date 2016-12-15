function Store() {
}

Store.prototype.store = function(data, cb) {
  this.request = data;
  cb();
};

Store.prototype.get = function(cb) {
  cb(null, this.request);
};

module.exports = Store;