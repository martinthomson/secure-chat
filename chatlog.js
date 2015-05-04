define(['require', 'roster', 'hkdf', 'util'], function(require) {

  var Roster = require('roster');
  var hkdf = require('hkdf');
  var util = require('util');

  /** A chat key is a key that has been provided by keyAgent. */
  function ChatKey(agent, rawKey) {
    this.identifier = agent.identifier
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
          .then(id => hkdf(counter, id, 'nonce', 12))
          .then(nonce => util.bsXor(nonce, counter));
        key: this._key
      });
    }
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
  ChatOpcode.REKEY = new ChatOpcode(0);
  ChatOpcode.MESSAGE = new ChatOpcode(1);

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
    ChatOperation.call(this, ChatOpcode.REKEY, actor);
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

  RekeyOperation.keyLength = 16;
  RekeyOperation.generateKey = function() {
    return crypto.getRandomValues(RekeyOperation.keyLength);
  }

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
        validUser: userRoster.find(peerRoster)
          .then(isAllowed),
        actor: peerRoster.find(peerAgent)
          .then(isAllowed)
      }).then(r => {
        return {
          actor: r.actor,
          actorRoster: peerRoster
        };
      })
    );
  };

  RekeyOperation.decode = function(agent, userRoster, parser) {
    return util.promiseDict({
      lengths: PublicEntity.lengths,
      agentId: agent.identity
    }).then(r => {
      var lengths = r.lengths;
      var agentId = r.agentId;

      // Who sent this?
      var peerAgent = new PublicIdentity(parser.next(lengths.identifier));
      var peerUser = new PublicIdentity(parser.next(lengths.identifier));

      var count = (parser.next(1)[0] << 8) | (parser.next(1)[0]);
      var pieceSize = lengths.identifier + RekeyOperation.keyLength;
      var found = util.bsDivide(parser.next(count * pieceSize), pieceSize)
        .map(piece => new util.Parser(piece))
        .find(pieceParser => util.bsEqual(agentId,
                                          pieceParser.next(lengths.identifier)));
      var rawKey;
      if (found) {
        rawKey = found.next(RekeyOperation.keyLength);
      }
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
            r => agent.maskKey(r.actor.share, encrypted)
              .then(key => new RekeyOperation(r.actor, r.actorRoster, rawKey, []))
          )
      });
    }).then(r => r.op);
  };

  function MessageOperation(actor, message) {
  }
  MessageOperation.prototype = util.mergeDict({
    _getIV: function() {
      var iv = new Uint8Array(12);
      for (var i = 0; i < 6; ++i) {
        iv[iv.length - 1 - i] = (this.log.length / Math.pow(256, i)) & 0xff;
      }
      return iv;
    },

    encode: function(key, iv) {
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
  MessageOperation.decode = function(user, roster, key, parser) {
  };

  ChatOperation.decode = function(user, roster, key, parser) {
    var opcode = ChatOpcode.decode(parser);
    if (opcode.equals(ChatOpcode.REKEY)) {
      return RekeyOperation.decode(user, roster, parser);
    }
    if (opcode.equals(ChatOpcode.MESSAGE)) {
      return MessageOperation.decode(user, roster, key, parser);
    }
    throw new Error('invalid opcode ' + opcode);
  };


  function ChatLog(roster, user) {
    this.log = [];
    this.roster = roster;
    this.identity = roster.identity;
    this.user = user;
  }
  ChatLog.prototype = {

    _addOperation: function(op) {
      op.encode(
    },

      rekey: function(user) {
        var op = new RekeyOperation(this.user, RekeyOperation.generateKey(),
                                    this.roster.members());
      return this._addOperation(op);
    }
  };
  return ChatLog;
});
