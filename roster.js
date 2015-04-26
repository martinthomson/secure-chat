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

  var RosterOperation = {
    CHANGE: 0,
    SHARE: 1,

    encode: v => new Uint8Array([v]),
    decode: buf => {
      var v = new Uint8Array(buf)[0];
      if (v !== RosterOperation.CHANGE &&
          v !== RosterOperation.SHARE) {
        throw new Error('invalid operation');
      }
      return v;
    }
  };

  /**
   * Create a new roster entry.
   *
   * @op the RosterOperation to use
   * @policy an EntityPolicy instance
   * @subject the entity that is being changed; a PublicEntity.
   * @actor the entity generating the entry; if this.encode() is needed, this
   *        will need to be an instance of Entity; otherwise PublicEntity is OK.
   * @hash a promise to a hash of the current last entry in the log
   */
  function RosterEntry(values) {
    util.mergeDict([values], this);
  }

  /** Encodes this, taking a promise to the hash of the last value */
  RosterEntry.prototype.encode = function(lastEntryHash) {
    var pieces = [RosterOperation.encode(this.operation) ];
    if (this.operation === RosterOperation.CHANGE) {
      pieces.push(this.subject.identity);
      pieces.push(this.policy.encode());
    } else if (this.operation === RosterOperation.SHARE) {
      pieces.push(this.subject.share);
    } else {
      throw new Error('invalid operation');
    }
    pieces.push(this.actor.identity);
    pieces.push(lastEntryHash);
    return Promise.all(pieces)
      .then(encodedPieces => {
        var msg = util.bsConcat(encodedPieces);
        return this.actor.sign(msg)
          .then(sig => util.bsConcat([msg, sig]))
      });
  };

  // Calculate some lengths based on the same principle: generate a real value
  // and work out how big it is.  When the algorithm details are nailed down,
  // this won't be necessary.
  RosterEntry.lengths = (function() {
    return PublicEntity.lengths.then(
      entityLengths => util.promiseDict(
        util.mergeDict([entityLengths], {
          operation: util.bsLength(RosterOperation.encode(RosterOperation.CHANGE)),
          policy: util.bsLength(EntityPolicy.NONE.encode()),
          hash: allZeroHash.then(util.bsLength)
        }))
    );
  }());

  RosterEntry._decodeEntry = function(parser, lengths) {
    var entry = {
      operation: RosterOperation.decode(parser.next(lengths.operation))
    };

    if (entry.operation === RosterOperation.CHANGE) {
      entry.subject = new PublicEntity(parser.next(lengths.identifier));
      entry.policy = EntityPolicy.decode(parser.next(lengths.policy));
    } else if (entry.operation === RosterOperation.SHARE) {
      entry.share = parser.next(lengths.share);
    } else {
      throw new Error('invalid operation');
    }
    entry.actor = new PublicEntity(parser.next(lengths.identifier));
    return entry;
  };

  RosterEntry._checkHashAndSig = function(actor, lastHash, hash,
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
  RosterEntry.decode = function(parser, lastHash) {
    return RosterEntry.lengths.then(lengths => {
      var startPosition = parser.position;

      var entry = RosterEntry._decodeEntry(parser, lengths);

      var hash = parser.next(lengths.hash);
      var signatureMessage = parser.range(startPosition, parser.position);
      var signature = parser.next(lengths.signature);
      return RosterEntry._checkHashAndSig(
        entry.actor, (lastHash || allZeroHash),
        hash, signatureMessage, signature
      ).then(_ => new RosterEntry(entry));
    });
  };

  /** Used internally by the roster to track the status of entities in the roster */
  function CacheEntry(subject, policy) {
    PublicEntity.call(this, subject.identity, subject.share);
    this.policy = policy;
  }
  CacheEntry.prototype = Object.create(PublicEntity.prototype);

  function Roster(entries) {
    this.entries = [].concat(entries);
    this.lastHash = c.digest(HASH, this.last);
  }

  Roster.prototype = {
    get last() {
      return this.entries[this.entries.length - 1];
    },

    getCachedPolicy: function(entity) {
      return entity.identifier.then(id => {
        return this.cache[util.base64url.encode(id)];
      });
    },

    _updateCacheEntry: function(entry) {
      return Roster._cacheKey(entry.subject)
        .then(k => {
          if (entry.operation === RosterOperation.CHANGE) {
            if (!this.cache[k]) {
              this.cache[k] = new CacheEntry(entry.subject, entry.policy);
            } else if (entry.policy.member) {
              this.cache[k].policy = entry.policy;
            } else {
              delete this.cache[k];
            }
          } else if (entry.operation === RosterOperation.SHARE) {
            if (!this.cache[k]) {
              throw new Error('not a member');
            }
            cache[k].share = entry.share;
          } else {
            throw new Error('invalid operation');
          }
        });
    },

    /** Takes an encoded entry (ebuf) and a promise for the hash of the last
     * message (lastHash) and updates the cache based on that information.  This
     * rejects if the entry isn't valid (see RosterEntry.decode).  */
    _updateEncodedCacheEntry: function(ebuf, lastHash) {
      return RosterEntry.decode(new util.Parser(ebuf), lastHash)
        .then(entry => {
          var check = Promise.resolve();
          // If lastHash is unset, then the entry is the first and the change is
          // automatically permitted.
          if (entry.operation === RosterOperation.CHANGE && lastHash) {
            return this._checkChange(entry.actor, entry.subject, entry.policy);
          }
          return check.then(_ => this._updateCacheEntry(entry));
        });
    },

    /** Updates all entries in the cache based on the entire transcript. It
     * returns the value of this.lastHash. */
    rebuildCache: function() {
      this.cache = {};
      // For each entry, simultaneously update the cache, and calculate the hash
      // of the entry.  The hash is passed on for validating the next message.

      // Note that this updates lastHash directly, which blocks updates.
      return this.lastHash = this.entries.reduce(
        (lastHash, ebuf) => {
          return util.promiseDict({
            entry: this._updateEncodedCacheEntry(ebuf, lastHash),
            hash: c.digest(HASH, ebuf)
          }).then(result => result.hash);
        }, null);
    },

    /** Find a cached entry for the given entity.  This will resolve
     * successfully to undefined if there are no entries. */
    find: function(entity) {
      return Roster._cacheKey(entity).then(k => this.cache[k]);
    },

    /** Find a cached policy for the given entity.  This will resolve
     * successfully with EntityPolicy.NONE if there are no entries. */
    findPolicy: function(entity) {
      return this.find(entity).then(v => v ? v.policy : EntityPolicy.NONE);
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
            this.entries.push(encoded);
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
        .then(_ => this._addEntry(new RosterEntry({
          operation: RosterOperation.CHANGE,
          policy: policy,
          subject: subject,
          actor: actor
        })));
    },

    share: function(actor) {
      return this.findPolicy(actor).then(policy => {
        if (!policy.member) {
          throw new Error('not a member');
        }
        return this._addEntry(new RosterEntry({
          operation: RosterOperation.SHARE,
          share: actor.share,
          actor: actor
        }));
      });
    },

    toJSON: function() {
      return this.entries.map(util.bsHex);
    }
  };

  /** A simple helper that determines the cache key for an entity. */
  Roster._cacheKey = function(entity) {
    return entity.identity.then(id => util.base64url.encode(id));
  };

  /**
   * Creates a new roster.  Only the creator option is mandatory here.  By
   * default, the creator adds them selves; by default the policy is
   * EntityPolicy.ADMIN.
   */
  Roster.create = function(creator, firstMember, policy) {
    firstMember = firstMember || creator;
    policy = policy || EntityPolicy.ADMIN;
    if (!policy.member || !policy.add) {
      throw new Error('first member must have "member" and "add" privileges');
    }
    var entry = new RosterEntry({
      operation: RosterOperation.CHANGE,
      policy: policy,
      subject: firstMember,
      actor: creator
    });
    return entry.encode(allZeroHash)
      .then(encoded => new Roster(encoded))
      .then(roster => {
        return roster.rebuildCache().then(_ => roster);
      });
  };

  Roster.decode = function(buf) {
    return RosterEntry.lengths
      .then(len => new Roster(chunkArray(buf, len.entry)))
      .then(roster => {
        return roster.rebuildCache().then(_ => roster);
      });
  };

  function UserRoster() {
    this.entries = [];
  }

  return {
    RosterEntry: RosterEntry, // TODO don't export
    RosterOperation: RosterOperation,
    Roster: Roster,
    UserRoster: UserRoster
  };
});
