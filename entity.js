define(['require', 'util'], function(require) {
  'use strict';

  var c = crypto.subtle;
  var util = require('util');

  const CURVE = 'P-256';
  const ECDSA_KEY = { name: 'ECDSA', namedCurve: CURVE };
  const ECDSA_SIGN = { name: 'ECDSA', hash: 'SHA-256' };
  const ECDH = { name: 'ECDH', namedCurve: CURVE };
  // These identify P-256, which we need until we support 'raw'
  const SPKI_PREFIX = new Uint8Array([
    48, 86, 48, 16, 6, 4, 43, 129, 4, 112, 6, 8,
    42, 134, 72, 206, 61, 3, 1, 7, 3, 66, 0
  ]);

  function importPublicKey(pub, alg, usages) {
    return Promise.resolve(pub).then(pubKey => {
      if (pubKey instanceof CryptoKey) {
        return pubKey;
      }
      console.log(pubKey);
      return c.importKey('spki', util.bsConcat([SPKI_PREFIX, pubKey]),
                         alg, true, usages);
    });
  };

  /** This is the public identity of a participant. Both sig and ecdh are either
   * the raw public key (as a BufferSource, or a Web Crypto CryptoKey public
   * value.
   *
   * The signing key (sig) is mandatory; the ECDH share (ecdh) is optional.  You
   * don't get an ECDH until the actor advertises a share.
   * Both sig and ecdh take an BufferSource, a CryptoKey or a promise for a CryptoKey.
   */
  function PublicEntity(sig, ecdh) {
    this.signPublic = importPublicKey(sig, ECDSA_KEY, ['verify']);
    if (ecdh) {
      this.share = ecdh;
    }
  }
  PublicEntity.prototype = {
    /** Verify that a message came from this entity. */
    verify: function(signature, message) {
      return this.signPublic
        .then(key => c.verify(ECDSA_SIGN, key, signature, message));
    },

    /** Returns a promise with the raw public signature key. */
    get identity() {
      return this.signPublic
        .then(key => c.exportKey('spki', key))
        .then(spki => new Uint8Array(spki, SPKI_PREFIX.length));
    },

    /** Returns a promise with the raw ECDH share. Reject is there is none. */
    get share() {
      if (!this.ecdhPublic) {
        return null;
      }
      return this.ecdhPublic
        .then(key => c.exportKey('spki', key))
        .then(spki => new Uint8Array(spki, SPKI_PREFIX.length));
    },

    set share(pub) {
      this.ecdhPublic = importPublicKey(pub, ECDH, ['deriveBits']);
    }
  };

  /** An entity has all the private keying material.  It is duck-typed into
   * PublicEntity so that it can be used to share information. */
  function Entity() {
    this.signKey = c.generateKey(ECDSA_KEY, false, ['sign', 'verify']);
    this.ecdhKey = c.generateKey(ECDH, false, ['deriveBits']);
  }
  Entity.prototype = {
    verify: function(signature, message) {
      return this.signKey
        .then(pair => c.verify(ECDSA_SIGN, pair.publicKey,
                               signature, message));
    },

    get identity() {
      return this.signKey
        .then(pair => c.exportKey('spki', pair.publicKey))
        .then(spki => new Uint8Array(spki, SPKI_PREFIX.length));
    },

    get share() {
      return this.ecdhKey
        .then(pair => c.exportKey('spki', pair.publicKey))
        .then(spki => new Uint8Array(spki, SPKI_PREFIX.length));
    },

    /** This shouldn't be necessary, since objects of type Entity behave exactly
     * like the value that this returns. */
    get publicEntity() {
      return Promise.all([this.signKey, this.ecdhKey])
        .then(keys => new PublicEntity(keys[0].publicKey, keys[1].publicKey));
    },

    /** Encodes into a binary form.  This isn't reversible:
     * PublicEntity.decode() can be used to get a PublicEntity instance from the
     * encoded form, but the private keys will be lost. */
    encode: PublicEntity.prototype.encode,

    /** Returns a promise to generate a signature over the message. */
    sign: function(message) {
      return this.signKey
        .then(pair => c.sign(ECDSA_SIGN, pair.privateKey, message));
    }
  };

  // Calculate some lengths based on the same principle: generate a real value
  // and work out how big it is.  When the algorithm details are nailed down,
  // this won't be necessary.
  PublicEntity.lengths = (function() {
    var dummyEntity = new Entity();
    return util.promiseDict({
      identifier: dummyEntity.identity.then(util.bsLength),
      share: dummyEntity.share.then(util.bsLength),
      signature: dummyEntity.sign(new Uint8Array(1)).then(util.bsLength)
    });
  }());

  return {
    Entity: Entity,
    PublicEntity: PublicEntity
  };
});
