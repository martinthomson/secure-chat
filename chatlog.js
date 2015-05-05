define(['require', 'roster', 'hkdf', 'util'], function(require) {

  var Roster = require('roster');
  var hkdf = require('hkdf');
  var util = require('util');
  var PublicEntity = require('entity').PublicEntity;
  var Entity = require('entity').Entity;

  function encode16(v) {
    if (v !== (v & 0xffff)) {
      throw new Error('not a suitable 16 bit number: ' + v);
    }
    var result = new Uint8Array(2);
    result[0] = v >>> 8;
    result[1] = v & 0xff;
    return result;
  }

  function decode16(parser) {
    var buf = parser.next(2);
    return (buf[0] << 8) | buf[1];
  }

  /** A chat key is a key that has been provided by the identified agent. */
  function ChatKey(agent, rawKey) {
    this.identity = agent.identity
      .then(id => hkdf(id, rawKey, 'keyid', ChatKey.idLength));
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
      var counter = util.bsConcat([ new Uint8Array(10), encode16(seqno) ]);
      return util.promiseDict({
        nonce: sender.identity
          .then(id => hkdf(new Uint8Array(1), id, 'nonce', 12))
          .then(nonce => util.bsXor(nonce, counter)),
        key: this._key
      });
    }
  };
  ChatKey.keyLength = 16;
  ChatKey.idLength = 16;
  ChatKey.generateKey = function() {
    return crypto.getRandomValues(new Uint8Array(ChatKey.keyLength));
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
      var pieces = [
        this.opcode.encode(),
        this.actor.identity,
        this.actorRoster.identity,
        encode16(this.members.length)
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
    var isAllowed = entity => {
      if (!entity) {
        throw new Error('user not permitted to rekey');
      }
      return entity;
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
    var count = decode16(parser);
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

  RekeyOperation.decode = function(parser, agent, userRoster, start) {
    return util.promiseDict({
      lengths: PublicEntity.lengths,
      agentId: agent.identity
    }).then(r => {
      var lengths = r.lengths;

      // Who sent this?
      var peerAgent = new PublicEntity(parser.next(lengths.identifier));
      var peerUser = new PublicEntity(parser.next(lengths.identifier));

      var encryptedKey = RekeyOperation._findOurEncryptedKey(parser, r.agentId,
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

    _encodeContent: function() {
      if (this.binary.byteLength > 0xffff) {
        throw new Error('message is too long to encode');
      }
      return this.binary;
    },

    encode: function(key, seqno) {
      var content = this._encodeContent();
      var op = new Uint8Array(1); // TODO: use the internal message parts for something more than text
      return Promise.all([
        op,
        content,
        this.actor.sign(util.bsConcat([ op, content ])) // TODO: discriminator
      ]).then(cleartext => key.encrypt(this.actor, seqno,
                                       util.bsConcat(cleartext)))
        .then(encrypted => Promise.all([
            this.opcode.encode(),
            this.actor.identity,
            key.identity,
            encode16(seqno),
            encode16(encrypted.byteLength),
            encrypted
        ])).then(util.bsConcat);
    }
  }, Object.create(ChatOperation.prototype));

  Object.defineProperty(EncryptedOperation.prototype, 'text', {
    get: function() {
      if (typeof this.message === 'string') {
        return this.message;
      }
      return new TextDecoder('utf-8').decode(this.message);
    }
  });
  Object.defineProperty(EncryptedOperation.prototype, 'binary', {
    get: function() {
      if (typeof this.message === 'string') {
        return new TextEncoder('utf-8').encode(this.message);
      }
      return this.message;
    }
  });

  EncryptedOperation.decode = function(parser, user, roster, keyLookup) {
    return PublicEntity.lengths.then(
      lengths => {
        var actor = new PublicEntity(parser.next(lengths.identifier));
        var keyid = parser.next(ChatKey.idLength)
        var key = keyLookup(keyid);
        if (!key) {
          throw new Error('no key for keyid: ' + util.base64url.encode(keyid));
        }
        var seqno = decode16(parser);
        var len = decode16(parser);
        var encrypted = parser.next(len);
        return key.decrypt(actor, seqno, encrypted)
          .then(cleartext => {
            var ctparser = new util.Parser(cleartext);
            var op = ctparser.next(1);
            if (op[0] !== 0) {
              throw new Error('unknown operation');
            }
            var clen = ctparser.remaining - lengths.signature;
            var content = ctparser.next(clen);
            var sig = ctparser.next(lengths.signature);
            return actor.verify(sig, util.bsConcat([ op, content ]))
              .then(ok => {
                if (!ok) {
                  throw new Error('invalid signature on encrypted message');
                }
              })
              .then(_ => new EncryptedOperation(actor, content));
          })
      }
    );
  };

  ChatOperation.decode = function(parser, user, roster, keyLookup) {
    var start = parser.mark();
    var opcode = ChatOpcode.decode(parser);
    if (opcode.equals(ChatOpcode.KEY)) {
      return RekeyOperation.decode(parser, user, roster, start);
    }
    if (opcode.equals(ChatOpcode.ENCRYPTED)) {
      return EncryptedOperation.decode(parser, user, roster, keyLookup);
    }
    throw new Error('invalid opcode ' + opcode);
  };

  /** A log of chat messages.  Note that unlike the roster, there is no strong
   * ordering of this log.  The log is only loosely ordered.
   *
   * @roster(UserRoster) the roster that this chat log covers
   * @agent(Entity) the actor that will doing things
   * @user(AgentRoster) the roster for that user (used for its identity only)
   */
  function ChatLog(roster, agent, user) {
    this.log = []; // encoded
    this.messages = []; // decoded
    this.roster = roster;
    this.identity = roster.identity;
    this.agent = agent;
    this.user = user;
    this._keystore = {};
  }
  ChatLog.prototype = {
    encode: function() {
      return util.bsConcat(this.log);
    },

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
      return this._addOperation(new RekeyOperation(this.agent, this.user,
                                                   rawKey,
                                                   this.roster.members()));
    },

    send: function(message) {
      return this._addOperation(new EncryptedOperation(this.agent, message));
    },

    _updateKey: function(rekeyAgent, rawKey) {
      var k = new ChatKey(rekeyAgent, rawKey);
      this._key = k;
      this._seqno = 0;
      return k.identity
        .then(id => this._keystore[util.base64url.encode(id)] = k);
    },

    _update: function(op) {
      if (op.opcode.equals(ChatOpcode.KEY)) {
        return this._updateKey(op.actor, op.key);
      }
      if (op.opcode.equals(ChatOpcode.ENCRYPTED)) {
        this.messages.push(op);
      }
    },

    _addOperation: function(op, encoded) {
      return util.promiseDict({
        logEntry: encoded || op.encode(this._key, this._seqno++),
        update: this._update(op)
      }).then(r => {
        this.log.push(r.logEntry);
        return r.logEntry;
      });
    },

    _decodeAndAdd: function(parser) {
      var startPosition = parser.mark();
      return PublicEntity.lengths.then(
        lengths => ChatOperation.decode(parser, this.agent, this.roster,
                                        id => this._getKey(id))
          .then(op => {
            var encoded = parser.marked(startPosition);
            return this._addOperation(op, encoded);
          })
      );
    },

    _getKey: function(kid) {
      return this._keystore[util.base64url.encode(kid)];
    }
  };
  return {
    ChatKey: ChatKey,
    ChatLog: ChatLog
  };
});
