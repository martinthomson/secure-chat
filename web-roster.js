define(['require', 'web-util', 'web-entity', 'web-policy'], function(require) {
  'use strict';

  var c = crypto.subtle;
  var util = require('web-util');
  var EntityPolicy = require('web-policy');
  var PublicEntity = require('web-entity').PublicEntity;

  var HASH = 'SHA-256';
  // Hash some junk and then change the output to zeros.  Which allows for hash
  // agility without hard coding the hash length.
  var allZeroHash = c.digest(HASH, new Uint8Array(1)).then(h => {
    h = new Uint8Array(h);
    h.fill(0);
    return h;
  });


  /**
   * Create a new roster entry.
   *
   * @policy an EntityPolicy instance
   * @subject the entity that is being changed; a PublicEntity.
   * @actor the entity generating the entry; if this.encode() is needed, this
   *        will need to be an instance of Entity; otherwise PublicEntity is OK.
   * @hash a promise to a hash of the current last entry in the log
   */
  function RosterEntry(policy, subject, actor, hash) {
    this.policy = policy;
    this.subject = subject;
    this.actor = actor;
    this.lastEntryHash = hash;
  }
  RosterEntry.prototype = {
    encode: function() {
      return Promise.all([this.policy.encode(), this.subject.identity,
                          this.actor.identity, this.lastEntryHash])
        .then(pieces => {
          var msg = util.bsConcat(pieces);
          return this.actor.sign(msg)
            .then(sig => util.bsConcat([msg, sig]))
        });
    }
  };
  // Calculate some lengths based on the same principle: generate a real value
  // and work out how big it is.  When the algorithm details are nailed down,
  // this won't be necessary.
  RosterEntry.lengths = (function() {
    return PublicEntity.lengths.then(
      entityLengths => util.promiseDict(util.mergeDict([{
        policy: util.bsLength(EntityPolicy.NONE.encode()),
        hash: allZeroHash.then(util.bsLength)
      }, entityLengths]))
    );
  }());

  /** Decode the buffer into an entry.  Note that this produces a RosterEntry
   * that can't be used with encode.  This rejects if the entry isn't valid.
   *
   * @buf is the raw bytes of the entry
   * @lastHash is a promise for a hash of the last message (which will be turned
   *           into the all zero value if omitted).
   */
  RosterEntry.decode = function(buf, lastHash) {
    return RosterEntry.lengths.then(lengths => {
      var pos = 0;
      var nextChunk = len => {
        var chunk = buf.slice(pos, pos + len);
        pos += len;
        return chunk;
      };

      var policy = EntityPolicy.decode(nextChunk(lengths.policy));
      var actor = new PublicEntity(nextChunk(lengths.identifier));
      var pSubject = PublicEntity.decode(nextChunk(lengths.entity));
      var hash = nextChunk(lengths.hash);

      var checkHash = (lastHash || allZeroHash).then(h => {
        if (!util.arrayBufferEqual(h, hash)) {
          throw new Error('invalid hash in entry');
        }
      });

      var signatureInput = buf.slice(0, pos);
      var verifySig = actor.verify(nextChunk(lengths.signature), signatureInput)
          .then(ok => {
            if (!ok) {
              throw new Error('invalid signature on entry');
            }
          });
      return Promise.all([pSubject, verifySig, checkHash])
        .then(r => new RosterEntry(hash, policy, actor, r[0]));
    });
  };

  function AgentRoster(initialEntry) {
    this.entries = [initialEntry];
    this.updateCache();
  }
  AgentRoster.prototype = {
    get tail() {
      return this.entries[this.entries.length - 1];
    },

    get tailHash() {
      return c.digest(HASH, this.tail);
    },

    getCachedPolicy: function(entity) {
      return entity.identifier.then(id => {
        return this.cache[util.base64url.encode(id)];
      });
    },

    updateCache: function() {
      this.cache = {};
      this.entries.reduce((p, e) => {
        return p.then(_ => {
          // TODO
          this.cache[util.base64url.encode(id)];
        });
      });
    },

    change: function(actor, subject, policy) {
      // TODO
    },

    toJSON: function() {
      return this.entries.map(util.bsHex);
    }
  };
  AgentRoster.create = function(creator, policy) {
    var msg = new RosterEntry(policy, creator, creator, allZeroHash);
    return msg.encode(creator)
      .then(encoded => new AgentRoster(encoded));
  };

  function UserRoster() {
    this.entries = [];
  }

  return {
    RosterEntry: RosterEntry, // TODO don't export
    AgentRoster: AgentRoster,
    UserRoster: UserRoster
  };
});
