'use strict';

const ACTION_CREATE = 0;
const ACTION_ADD = 1;
const ACTION_REMOVE = 2;

const LENGTH_LAST_MAC = 32;
const LENGTH_ACTION = 1;
const LENGTH_IDENTITY = 65;
const LENGTH_SIGNATURE = 65;

var crypto = require('crypto');
var assert = require('assert');

function RosterEntry(buf) {
  assert.equal(buf.length, LENGTH_LAST_MAC + LENGTH_ACTION +
               LENGTH_IDENTITY, LENGTH_SIGNATURE);
  this.data = buf;
}

RosterEntry.prototype = {
  mac: function() {
    var sha = crypto.createHash('sha256');
    sha.update(this.data);
    return sha.digest();
  },

  get lastMac() {
    return this.data.slice(0, LENGTH_LAST_MAC);
  },
  get action() {
    return this.data.readUIntBE(LENGTH_LAST_MAC, LENGTH_ACTION);
  },
  get identity() {
    return this.data.slice(LENGTH_LAST_MAC + LENGTH_ACTION,
                           LENGTH_IDENTITY);
  },
  get signature() {
    return this.data.slice(LENGTH_LAST_MAC + LENGTH_ACTION + LENGTH_IDENTITY);
  }
};

RosterEntry.create = function(entity, lastEntry, action, identity) {
  var actionBuf = new Buffer(LENGTH_ACTION);
  actionBuf.writeUIntBE(action, 0, LENGTH_ACTION);
  var data = Buffer.concat([lastEntry.mac(), actionBuf, identity]);
  var sig = crypto.createSign('id-ecPublicKey');
  sig.update(data);
  return Buffer.concat([data, sig.sign(privateKey)]);
};

module.exports = {
  RosterEntry: RosterEntry,
  ACTION_CREATE: ACTION_CREATE,
  ACTION_ADD: ACTION_ADD,
  ACTION_REMOVE: ACTION_REMOVE
};
