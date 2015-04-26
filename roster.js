define(['require', 'util', 'entity', 'policy'], function(require) {
  'use strict';

  var c = crypto.subtle;
  var util = require('util');
  var EntityPolicy = require('policy');
  var PublicEntity = require('entity').PublicEntity;

  var HASH = 'SHA-256';
  // Hash some junk and then change the output to zeros.  Which allows for hash
  // agility without hard coding the hash length.
  var allZeroHash = c.digest(HASH, new Uint8Array(1)).then(h => {
    h = new Uint8Array(h);
    h.fill(0);
    return h;
  });

  function RosterOpcode(op) {
    this.opcode = op;
  }
  RosterOpcode.prototype = {
    encode: function() {
      return new Uint8Array([this.opcode]);
    }
  };
  RosterOpcode.decode = function(buf) {
    return new RosterOpcode(new Uint8Array(buf)[0]);
  };
  RosterOpcode.CHANGE = new RosterOpcode(0);
  RosterOpcode.SHARE = new RosterOpcode(1);

  /**
   * Create a new roster entry.
   *
   * Takes a dictionary of values:
   *
   * operation: the RosterOpcode to use
   * for CHANGE, this also must include:
   * - policy: the new EntityPolicy to apply.
   * - subject: the entity that is being changed; a PublicEntity or Entity.
   * for SHARE, the actor is enough.
   *
   * actor the entity generating the entry; an Entity.
   */
  function RosterOperation(actor) {
    this.actor = actor;
  }

  /** Encodes this.  This takes a promise to the hash of the previous entry. */
  RosterOperation.prototype.encode = function(lastEntryHash) {
    var pieces = [].concat(
      this.opcode.encode(),
      this._encodeParts(),
      this.actor.identity,
      lastEntryHash
    );

    pieces.push(this.actor.identity);
    pieces.push(lastEntryHash);
    return Promise.all(pieces)
      .then(encodedPieces => {
        var msg = util.bsConcat(encodedPieces);
        return this.actor.sign(msg)
          .then(sig => util.bsConcat([msg, sig]))
      });
  };

  function ChangeOperation(actor, subject, policy) {
    RosterOperation.call(this, actor);
    this.opcode = RosterOpcode.CHANGE;
    this.subject = subject;
    this.policy = policy;
  }
  ChangeOperation.prototype = Object.create(RosterOperation.prototype);
  ChangeOperation.prototype._encodeParts = function() {
    return [ this.subject.identity, this.policy.encode() ];
  };

  function ShareOperation(actor) {
    RosterOperation.call(this, actor);
    this.opcode = RosterOpcode.SHARE;
    this.subject = actor;
  }
  ShareOperation.prototype = Object.create(RosterOperation.prototype);
  ShareOperation.prototype._encodeParts = function() {
    return [ this.subject.share ];
  };

  // Calculate some lengths based on the same principle: generate a real value
  // and work out how big it is.  When the algorithm details are nailed down,
  // this won't be necessary.
  RosterOperation.lengths = (function() {
    return PublicEntity.lengths.then(
      entityLengths => util.promiseDict(
        util.mergeDict([entityLengths], {
          opcode: RosterOpcode.CHANGE.encode().byteLength,
          policy: EntityPolicy.NONE.encode().byteLength,
          hash: allZeroHash.then(x => x.byteLength)
        }))
    );
  }());

  RosterOperation._decodeOperation = function(parser, lengths) {
    console.log(parser, new Uint8Array(parser._buf), parser.range(0, 1));
    var opcode = RosterOpcode.decode(parser.next(lengths.opcode));

    if (opcode === RosterOpcode.CHANGE) {
      var subject = new PublicEntity(parser.next(lengths.identifier));
      var policy = EntityPolicy.decode(parser.next(lengths.policy));
      var actor = new PublicEntity(parser.next(lengths.identifier));
      return new ChangeOperation(actor, subject, policy);
    }
    if (opcode === RosterOpcode.SHARE) {
      var share = parser.next(lengths.share);
      var actor = new PublicEntity(parser.next(lengths.identifier), share);
      return new ShareOperation(actor);
    }
    throw new Error('invalid operation: ' + opcode);
  };

  RosterOperation._checkHashAndSig = function(actor, lastHash, hash,
                                              signed, signature) {
    return Promise.all([
      actor.verify(signature, signed)
        .then(ok => {
          if (!ok) {
            throw new Error('invalid signature on entry');
          }
        }),
      lastHash.then(h => {
        if (!util.bsEqual(h, hash)) {
          throw new Error('invalid hash in entry');
        }
      })
    ]);
  };

  /** Decode the buffer into an entry.  Note that this produces a RosterEntry
   * that can't be used with encode.  This rejects if the entry isn't valid.
   *
   * @parser is the parser that will
   * @lastHash is a promise for a hash of the last message (which will be turned
   *           into the all zero value if omitted).
   */
  RosterOperation.decode = function(parser, lastHash) {
    return RosterOperation.lengths.then(lengths => {
      var startPosition = parser.position;

      var op = RosterOperation._decodeOperation(parser, lengths);

      var hash = parser.next(lengths.hash);
      var signatureMessage = parser.range(startPosition, parser.position);
      var signature = parser.next(lengths.signature);
      return RosterOperation._checkHashAndSig(
        op.actor, lastHash, hash,
        signatureMessage, signature
      ).then(_ => op);
    });
  };

  /** Used internally by the roster to track the status of entities in the roster */
  function CacheEntry(subject, policy) {
    PublicEntity.call(this, subject.identity, subject.share);
    this.policy = policy;
  }
  CacheEntry.prototype = Object.create(PublicEntity.prototype);

  function Roster(log) {
    this.log = [].concat(log);
    this.initialized = this._rebuildCache();
  }

  Roster.prototype = {
    /** A simple helper that determines the cache key for an entity. */
    _cacheKey: function(entity) {
      return entity.identity.then(id => util.base64url.encode(id));
    },

    /** Enacts the change in `entry` on the cache. */
    _updateCacheEntry: function(entry) {
      return this._cacheKey(entry.subject)
        .then(k => {
          if (entry.opcode === RosterOpcode.CHANGE) {
            if (!this.cache[k]) {
              this.cache[k] = new CacheEntry(entry.subject, entry.policy);
            } else if (entry.policy.member) {
              this.cache[k].policy = entry.policy;
            } else {
              delete this.cache[k];
            }
          } else if (entry.opcode === RosterOpcode.SHARE) {
            if (!this.cache[k]) {
              throw new Error('not a member');
            }
            this.cache[k].share = entry.subject.share;
          } else {
            throw new Error('invalid operation');
          }
        });
    },

    /** Takes an encoded entry (ebuf) and a promise for the hash of the last
     * message (lastHash) and updates the cache based on that information.  This
     * rejects if the entry isn't valid (see RosterEntry.decode).  */
    _updateEncodedCacheEntry: function(ebuf) {
      return RosterEntry.decode(new util.Parser(ebuf), this.lastHash)
        .then(entry => {
          var check = Promise.resolve();

          if (entry.opcode === RosterOpcode.CHANGE) {
            // If previousHash is allZeroHash, then the entry is the first and
            // the change is automatically permitted.  Otherwise, check.
            if (this.lastHash !== allZeroHash) {
              check = this._checkChange(entry.actor, entry.subject, entry.policy);
            }
          } else if (entry.opcode === RosterOpcode.SHARE) {
            check = this._checkShare(entry.subject);
          } else {
            throw new Error('invalid opcode');
          }
          return check.then(_ => this._addEntry(entry));
        });
    },

    /** Updates all entries in the cache based on the entire transcript. It
     * returns a promise that awaits the process. */
    _rebuildCache: function() {
      // Reset cache state.
      this.cache = {};
      this.lastHash = allZeroHash;

      return this.log.reduce(
        (prev, ebuf) => prev.then(_ => this._updateEncodedCacheEntry(ebuf)),
        Promise.resolve()
      );
    },

    /** Find a cached entry for the given entity.  This will resolve
     * successfully to undefined if there are no entries. */
    find: function(entity) {
      // This waits for this.lastHash so that it knows that the cache is
      // consistent with the last operation.
      return util.promiseDict({
        hash: this.lastHash,
        key: this._cacheKey(entity)
      }).then(r => this.cache[r.key]);
    },

    /** Find the cached policy for the given entity.  This will resolve
     * successfully with EntityPolicy.NONE if there are no entries. */
    findPolicy: function(entity) {
      return this.find(entity).then(v => v ? v.policy : EntityPolicy.NONE);
    },

    /** Find the cached share for the given entity.  This will resolve
     * successfully with null if there are no entries. */
    findShare: function(entity) {
      return this.find(entity).then(v => v ? v.share : null);
    },

    /** Determines if a given change in policy is permitted.  Note that this
     * will give the wrong answer for changes to an actors own policy unless
     * (actor === subject).
     */
    canChange: function(actor, subject, proposed) {
      if (actor === subject) {
        // A member can always reduce their own capabilities.  But only if their
        // old policy isn't already void (i.e., EntityPolicy.NONE).
        return this.findPolicy(actor)
          .then(oldPolicy =>
                !EntityPolicy.NONE.subsumes(oldPolicy) &&
                oldPolicy.subsumes(proposed));
      }

      return util.promiseDict({
        actor: this.findPolicy(actor),
        subject: this.findPolicy(subject)
      }).then(policies => policies.actor.canChange(policies.subject, proposed));
    },
    /** Calls canChange and throws if it returns false. */
    _checkChange: function(actor, subject, proposed) {
      return this.canChange(actor, subject, proposed)
        .then(ok => {
          if (!ok) {
            throw new Error('change forbidden');
          }
        });
    },

    /** Appends an entry and returns the updated lastHash. */
    _addEntry: function(entry) {
      // This concurrently:
      //  - encodes the new message and records it
      //  - updates the cache of latest entries

      // Set a new promise value for lastHash as soon as we decide to commit to
      // any change. That way, subsequent calls are enqueued behind this.

      // Only resolve that promise when both parts of the operation are
      // complete.  That way, any attempt to add to the log (the official
      // transcript) will be assured to get a valid cache state.

      // Drawback: Though it shouldn't, if anything here fails for any reason,
      // the log can no longer be added to.  All calls to modify the log depend
      // on the value of the last hash being valid.  It *might* be possible to
      // back out a failed change, but that would need careful consideration.
      return this.lastHash = util.promiseDict({
        hash: entry.encode(this.lastHash)
          .then(encoded => {
            this.log.push(encoded);
            return c.digest(HASH, encoded);
          }),
        update: this._updateCacheEntry(entry)
      }).then(r => r.hash);
    },

    /** Enact a change in policy for the subject, triggered by actor.  This will
     * reject if the change is not permitted.
     */
    change: function(actor, subject, policy) {
      return this._checkChange(actor, subject, policy)
        .then(_ => this._addEntry(new ChangeOperation(actor, subject, policy)));
    },

    /** Basic check for membership */
    _checkShare: function(actor) {
      return this.findPolicy(actor).then(policy => {
        if (!policy.member) {
          throw new Error('not a member');
        }
      });
    },

    /** Add a share to this roster. */
    share: function(actor) {
      return this._checkShare(actor)
        .then(_ => this._addEntry(new ShareOperation(actor)));
    },

    toJSON: function() {
      return this.log.map(util.bsHex);
    }
  };

  /**
   * Creates a new roster.  Only the creator option is mandatory here.  By
   * default, the creator adds them selves; by default the policy is
   * EntityPolicy.ADMIN.  If the creator adds themself, this also adds their
   * share to the log.
   */
  Roster.create = function(actor, subject, policy) {
    subject = subject || actor;
    policy = policy || EntityPolicy.ADMIN;
    if (!policy.member || !policy.add) {
      throw new Error('first entry must have "member" and "add" privileges');
    }

    var roster = new Roster([]);

    // This bypasses validity checks, since the first entry is special.
    var p = roster.initialized
        .then(_ => roster._addEntry(new ChangeOperation(actor, subject, policy)));
    if (actor === subject) {
      p = p.then(_ => roster.share(actor));
    }
    return p.then(_ => roster);
  };

  Roster.decode = function(buf) {
    var roster = new Roster([]);
    var parser = new util.Parser(buf);
  };

  function UserRoster() {
  }

  return {
    Roster: Roster,
    UserRoster: UserRoster
  };
});
