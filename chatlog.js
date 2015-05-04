define(['require', 'roster', 'hkdf', 'util'], function(require) {

  var Roster = require('roster');
  var hkdf = require('hkdf');
  var util = require('util');
  var PublicEntity = require('entity').PublicEntity;
  var Entity = require('entity').Entity;

  /** A chat key is a key that has been provided by the identified agent. */
  function ChatKey(agent, rawKey) {
    this.identity = agent.identity
      .then(id => hkdf(id, rawKey, 'keyid', 16));
    this._key = crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false,
                                        [ 'encrypt', 'decrypt' ]);
  }
  ChatKey.prototype = {
    encrypt: function(sender, seqno, buf) {
      return this._nonceAndKey(sender, seqno)
        .then(r => crypto.subtle.encrypt({
          name: 'AES-GCM',
          iv: r.nonce
        }, r.key, buf));
    },

    decrypt: function(sender, seqno, buf) {
      return this._nonceAndKey(sender, seqno)
        .then(r => crypto.subtle.decrypt({
          name: 'AES-GCM',
          iv: r.nonce
        }, r.key, buf));
    },

    _nonceAndKey: function(sender, seqno) {
      if (seqno !== (seqno & 0xffff)) {
        throw new Error('bad seqno');
      }
      var counter = new Uint8Array(12);
      counter[10] = seqno >>> 8;
      counter[11] = seqno & 0xff;
      return util.promiseDict({
        nonce: sender.identity
          .then(id => hkdf(new Uint8Array(0), id, 'nonce', 12))
          .then(nonce => util.bsXor(nonce, counter)),
        key: this._key
      });
    }
  };
  ChatKey.keyLength = 16;
  ChatKey.idLength = 16;
  ChatKey.generateKey = function() {
    return crypto.getRandomValues(ChatKey.keyLength);
  };

  function ChatOpcode(op) {
    this.opcode = op;
  }
  ChatOpcode.prototype = {
    encode: function() {
      return new Uint8Array([this.opcode]);
    },
    equals: function(other) {
      return other instanceof ChatOpcode &&
        this.opcode === other.opcode;
    },
    toString: function() {
      return 'ChatOpcode(' + this.opcode + ')';
    }
  };
  ChatOpcode.decode = function(parser) {
    return new ChatOpcode(parser.next(1)[0]);
  };
  ChatOpcode.KEY = new ChatOpcode(0);
  ChatOpcode.ENCRYPTED = new ChatOpcode(1);

  function ChatOperation(opcode, actor) {
    this.opcode = opcode;
    this.actor = actor;
  }
  ChatOperation.prototype = {
    encode: function() {
      throw new Error('not implemented');
    },
  };

  function RekeyOperation(actor, actorRoster, key, members) {
    ChatOperation.call(this, ChatOpcode.KEY, actor);
    this.actorRoster = actorRoster;
    this.key = key;
    this.members = members || [];
  }
  RekeyOperation.prototype = util.mergeDict({
    _encipherKey: function() {
      return this.members.map(
        member => Promise.all([
          member.identity,
          this.actor.maskKey(member.share, this.key)
        ]).then(util.bsConcat)
      );
    },

    encode: function() {
      if (this.members.length > 0xffff) {
        throw new Error('too many members');
      }
      var count = new Uint8Array(2);
      count[0] = this.members.length >>> 8;
      count[1] = this.members.length & 0xff;
      var pieces = [
          this.opcode.encode(),
          this.actor.identity,
          this.actorRoster.identity,
          count
      ].concat(this._encipherKey());
      return Promise.all(pieces)
        .then(encodedPieces => {
          var msg = util.bsConcat(encodedPieces);
          return this.actor.sign(msg)
            .then(sig => util.bsConcat([ msg, sig ]));
        });
    }
  }, Object.create(ChatOperation.prototype));

  /** Finds the given peer agent and user.  Checks that peerUser is a member of
   * the userRoster, and that peerAgent is a member of the roster corresponding
   * to peerUser. */
  RekeyOperation._findActor = function(userRoster, peerAgent, peerUser) {
    var isAllowed = r => {
      if (!r) {
        throw new Error('user not permitted to rekey');
      }
      return r;
    };
    return Roster.findRoster(peerUser).then(
      peerRoster => util.promiseDict({
        user: userRoster.find(peerRoster)
          .then(isAllowed),
        actor: peerRoster.find(peerAgent)
          .then(isAllowed),
        actorRoster: peerRoster
      })
    );
  };

  RekeyOperation._findOurEncryptedKey = function(parser, agentId, lengths) {
    var count = (parser.next(1)[0] << 8) | (parser.next(1)[0]);
    var pieceSize = lengths.identifier + ChatKey.keyLength;
    var found = util.bsDivide(parser.next(count * pieceSize), pieceSize)
        .map(piece => new util.Parser(piece))
        .find(pieceParser => util.bsEqual(agentId,
                                          pieceParser.next(lengths.identifier)));
    // We allow for the possibility that someone encrypted this message
    // without including us.  That happens if we were just added or removed
    // and we haven't seen that message yet.  In that case, it's not an error,
    // so allow the decoding to proceed.
    //
    // A zero-length key is an OK input to pass to Entity.maskKey (below).  We
    // don't even have to be careful not to actually try to encrypt with that
    // key, WebCrypto will prevent us from importing a dud key.
    var encryptedKey = new Uint8Array(0);
    if (found) {
      encryptedKey = found.next(ChatKey.keyLength);
    }
    return encryptedKey;
  };

  RekeyOperation.decode = function(parser, agent, userRoster) {
    return util.promiseDict({
      lengths: PublicEntity.lengths,
      agentId: agent.identity
    }).then(r => {
      var lengths = r.lengths;
      var agentId = r.agentId;
      var start = parser.mark();

      // Who sent this?
      var peerAgent = new PublicIdentity(parser.next(lengths.identifier));
      var peerUser = new PublicIdentity(parser.next(lengths.identifier));

      var encryptedKey = RekeyOperation._findOurEncryptedKey(parser, agentId,
                                                             lengths);

      // TODO: this doesn't cover the opcode; want discriminator strings here.
      var msg = parser.marked(start);
      var sig = parser.next(lengths.signature);
      return util.promiseDict({
        signature: peerAgent.verify(sig, msg)
          .then(ok => {
            if (!ok) {
              throw new Error('signature on rekey invalid');
            }
          }),
        op: RekeyOperation._findActor(userRoster, peerAgent, peerUser)
          .then(
            r => agent.maskKey(r.actor.share, encryptedKey)
              .then(rawKey => new RekeyOperation(r.actor, r.actorRoster,
                                                 rawKey, []))
          )
      });
    }).then(r => r.op);
  };

  function EncryptedOperation(actor, message) {
    ChatOperation.call(this, ChatOpcode.ENCRYPTED, actor);
    this.message = message;
  }
  EncryptedOperation.prototype = util.mergeDict({
    encode: function(key, seqno) {
      return this._encodeParts()
        .then(parts => {
          var opcode = this.opcode.encode();
          var ad = util.bsConcat([ opcode ]);
          var message = util.bsConcat([ opcode ].concat(parts));
          return this.actor.sign(message)
            .then(sig => crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv,
                                                 additionalData: ad },
                                               key, util.bsConcat([message, sig])))
            .then(enc => {
              var len = new Uint8Array(1);
              len[0] = enc.byteLength;
              return util.bsConcat([len, enc]);
            });
        });
    }
  }, Object.create(ChatOperation.prototype));
  EncryptedOperation.decode = function(parser, user, roster, key) {
  };

  ChatOperation.decode = function(parser, user, roster, key) {
    var opcode = ChatOpcode.decode(parser);
    if (opcode.equals(ChatOpcode.KEY)) {
      return RekeyOperation.decode(parser, user, roster);
    }
    if (opcode.equals(ChatOpcode.ENCRYPTED)) {
      return EncryptedOperation.decode(parser, user, roster, key);
    }
    throw new Error('invalid opcode ' + opcode);
  };

  /** A log of chat messages.  Note that unlike the roster, there is no strong
   * ordering of this log.  The log is only loosely ordered.
   */
  function ChatLog(roster, user) {
    this.log = [];
    this.roster = roster;
    this.identity = roster.identity;
    this.user = user;
    this._keystore = {};
  }
  ChatLog.prototype = {

    decode: function(buf) {
      var parser = new util.Parser(buf);
      var loadRemainingOperations = _ => {
        if (parser.remaining <= 0) {
          return;
        }
        return this._decodeAndAdd(parser)
          .then(loadRemainingOperations);
      };
      return loadRemainingOperations();
    },

    rekey: function() {
      var rawKey = ChatKey.generateKey();
      return this._addOperation(new RekeyOperation(this.user, rawKey,
                                                   this.roster.members()))
        .then(op => {
          this._key = new ChatKey(this.user, rawKey);
          this._seqno = 0;
          return this._storeKey(this._key).then(_ => op);
        });
    },

    send: function(message) {
      return this._addOperation(new EncryptedOperation(this.user, message));
    },

    _addOperation: function(op) {
      op.encode(this._key, this._seqno++)
        .then(encoded => {
          this.log.push(encoded);
          return encoded;
        });
    },

    _decodeAndAdd: function(parser) {
      var startPosition = parser.mark();
      return PublicIdentity.lengths.then(
        lengths => ChatOperation.decode()
          .then({
          })
      );
    },

    _storeKey: function(k) {
      return k.identifier
        .then(id => this._keystore[util.base64url.encode(id)] = k);
    },

    _getKey: function(kid) {
      return this._keystore[util.base64url.encode(id)];
    }
  };
  return {
    ChatKey: ChatKey,
    ChatLog: ChatLog
  };
});
