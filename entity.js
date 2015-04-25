'use strict';

var crypto = require('crypto');

function Entity() {
  // have to coerce node into generating an EC key pair using ECDH
  this.keypair = crypto.createECDH('prime256v1');
  this.identity = this.keypair.generateKeys();
}

Entity.prototype = {
  sign: function(data) {
    var sig = crypto.createSign('id-ecPublicKey');
    sig.update(data);
    return sig.sign(this.keypair.getPrivateKey());
  }
};

Entity.verify = function(pubKey, data, signature) {
  var ver = crypto.createVerify('id-ecPublicKey');
  ver.update(data);
  return ver.verify(/* what the fuck goes here */ pubKey, signature);
};

module.exports = {
  Entity: Entity
};
