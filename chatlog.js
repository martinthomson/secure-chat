define(['require'], function(require) {
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

  function RekeyOperation(actor, key, members) {
    ChatOperation.call(this, ChatOpcode.REKEY, actor);
    this.key = key;
    this.members = members || [];
  }
  RekeyOperation.prototype = util.mergeDict({
    _encipherKey: function() {
      return Promise.all(this.members.map(
        member => Promise.all([
          member.identity,
          this.actor.maskKey(member.share, this.key)
        ]).then(parts => util.bsConcat(parts))
      ))
    },
    encode: function() {
      var len = new Uint16Array(1);
      len[0] = this.parts.reduce((total, part) => total + part.byteLength, 0);
      return Promise.resolve(util.bsConcat(
        [ this.opcode.encode(), len, this.actor.identity ]
          .concat(this._encipherKey())
      ));
    }
  }, Object.create(ChatOperation.prototype));

  RekeyOperation.keyLength = 16;
  RekeyOperation.generateKey = function() {
    return crypto.getRandomValues(RekeyOperation.keyLength);
  }

  RekeyOperation.decode = function(user, roster, parser) {
    return user.identity.then(id => {
      var len = new Uint16Array(parser.next(2))[0];
      var end = parser.position + len;

      // Determine who sent this.
      var peer = new PublicIdentity(parser.next(id.byteLength));
      // Find the key that was sent to us.
      var encrypted;
      while (parser.position < end) {
        var otherid = parser.next(id.byteLength);
        encrypted = parser.next(RekeyOperation.keyLength);
        if (util.bsEqual(id, otherid)) {
          parser.position = end;
        }
      }
      if (encrypted) {
        return roster.find(peer)
          .then(realPeer => user.maskKey(realPeer.share, encrypted))
          .then(key => new RekeyOperation(user, key, []));
      }
      return Promise.resolve(new RekeyOperation(user, null, []));
    });
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
          var ad = util.bsConcat([opcode]);
          var message = util.bsConcat([opcode].concat(parts));
          return this.actor.sign(message)
            .then(sig => crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv,
                                                 additionalData: ad },
                                               key, util.bsConcat([message, sig])))
            .then(enc => {
              var len = new Uint16Array(1);
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
