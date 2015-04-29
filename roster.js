define(['require', 'util', 'entity', 'policy', 'rosterop'], function(require) {
  'use strict';

  var c = crypto.subtle;
  var util = require('util');
  var EntityPolicy = require('policy');
  var PublicEntity = require('entity').PublicEntity;
  var Entity = require('entity').Entity;
  var RosterOperation = require('rosterop').RosterOperation;
  var RosterOpcode = require('rosterop').RosterOpcode;
  var ChangeOperation = require('rosterop').ChangeOperation;
  var ShareOperation = require('rosterop').ShareOperation;

  var HASH = 'SHA-256';
  // Hash some junk and then change the output to zeros.  Which allows for hash
  // agility without hard coding the hash length.
  var allZeroHash = c.digest(HASH, new Uint8Array(1)).then(h => {
    h = new Uint8Array(h);
    h.fill(0);
    return h;
  });

  /** A simple helper that determines the cache key for any entity with an
   * identity. */
  function cacheKey(entity) {
    return Promise.resolve(entity)
      .then(e => e.identity)
      .then(id => util.base64url.encode(id));
  }

  /** A simple store for rosters. */
  function AllRosters() {
    this.rosters = {};
  }
  AllRosters.prototype = {
    /** Register a roster.  This takes a second argument, the creator of the
     * roster for the case of self-registration of a roster.  That happens prior
     * to the identity of the roster being confirmed. */
    register: function(roster, creator) {
      return cacheKey(creator || roster)
        .then(k => this.rosters[k] = roster);
    },
    lookup: function(entity) {
      return cacheKey(entity).then(k => this.rosters[k]);
    }
  };
  var allRosters = new AllRosters();

  /** Used internally by the roster to track the status of entities in the roster */
  function CacheEntry(subject, policy) {
    PublicEntity.call(this, subject.identity, subject.share);
    this.policy = policy;
  }
  CacheEntry.prototype = Object.create(PublicEntity.prototype);

  // Calculate some lengths based on the same principle: generate a real value
  // and work out how big it is.  When the algorithm details are nailed down,
  // this won't be necessary.
  var itemLengths = (function() {
    return PublicEntity.lengths.then(
      entityLengths => util.promiseDict(
        util.mergeDict(entityLengths, {
          opcode: RosterOpcode.CHANGE.encode().byteLength,
          policy: EntityPolicy.NONE.encode().byteLength,
          hash: allZeroHash.then(x => x.byteLength)
        }))
    );
  }());

  /** Creates a roster. */
  function Roster() {
    this.log = [];
    this._rebuildCache();
  }

  Roster.prototype = {

    /** Find a cached entry for the given entity.  This will resolve
     * successfully to undefined if there are no entries.  Note that while there
     * is an outstanding write, this might not be up-to-date for affected
     * entries.
     */
    find: function(entity) {
      return cacheKey(entity).then(k => this.cache[k]);
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

    /** Enact a change in policy for the subject, triggered by actor.  This will
     * reject if the change is not permitted.
     */
    change: function(actor, subject, policy) {
      return this._addEntry(new ChangeOperation(actor, subject, policy));
    },

    /** Add a share to this roster. */
    share: function(actor) {
      return this._addEntry(new ShareOperation(actor));
    },

    /** Returns a promise for an array of all the active members in the roster.
     * That is, all those that have provided shares. */
    allShares: function() {
      return Promise.all(
        Object.keys(this.cache)
          .map(k => this.cache[k].share)
          .filter(s => !!s)
      );
    },

    encode: function() {
      return util.bsConcat(this.log);
    },

    /** Decodes a sequence of entries and adds them to the log. */
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

    toJSON: function() {
      return this.log.map(util.bsHex);
    },

    /** Determines if a given change in policy is permitted.  Note that this
     * will give the wrong answer for changes to an actors own policy unless
     * (actor === subject).
     */
    _canChange: function(actor, subject, proposed) {
      // Find the existing policies for the two parties and see if this is OK.
      return util.promiseDict({
        actorId: actor.identity,
        subjectId: subject.identity,
        actorPolicy: this.findPolicy(actor),
        oldPolicy: this.findPolicy(subject)
      }).then(
        result => {
          console.log(result);
          // A member can always reduce their own capabilities.  But only if
          // their old policy isn't already void (i.e., EntityPolicy.NONE).
          if (util.bsEqual(result.actorId, result.subjectId)) {
            return !EntityPolicy.NONE.subsumes(result.oldPolicy) &&
              result.oldPolicy.subsumes(proposed);
          }
          return result.actorPolicy.canChange(result.oldPolicy, proposed);
        }
      );
    },

    /** Calls canChange and throws if it returns false. */
    _checkChange: function(actor, subject, proposed) {
      return this._canChange(actor, subject, proposed)
        .then(ok => {
          if (!ok) {
            throw new Error('change forbidden');
          }
        });
    },

    /** Check that the addition of a roster is OK. */
    _checkRosterChange: function(actor, actorRoster, subject, proposed) {
      return Promise.all([
        this._checkChange(actorRoster, subject, proposed),
        actorRoster
          .then(roster => roster.find(actor))
          .then(found => {
            if (!found) {
              throw new Error('actor is not in advertised roster');
            }
          })
      ]);
    },

    /** Basic check for membership */
    _checkShare: function(actor) {
      return this.findPolicy(actor).then(policy => {
        if (!policy.member) {
          throw new Error('not a member');
        }
      });
    },

    /** Determines if the given change is acceptable. */
    _validateEntry: function(entry) {
      // If this is the first entry, no checks.  A share operation will cause
      // the roster to become busted, so don't permit that.
      if (this._resolveIdentity && !entry.opcode.equals(RosterOpcode.SHARE)) {
        return Promise.resolve();
      }

      if (entry.opcode.equals(RosterOpcode.CHANGE)) {
        return this._checkChange(entry.actor, entry.subject, entry.policy);
      }
      if (entry.opcode.equals(RosterOpcode.CHANGE_ROSTER)) {
        return this._checkRosterChange(entry.actor, entry.actorRoster,
                                       entry.subject, entry.policy);
      }
      if (entry.opcode.equals(RosterOpcode.SHARE)) {
        return this._checkShare(entry.subject);
      }
      throw new Error('invalid opcode');
    },

    /** Enacts the change in `entry` on the cache. */
    _updateCacheEntry: function(k, entry) {
      if (entry.opcode.equals(RosterOpcode.CHANGE)) {
        if (!this.cache[k]) {
          this.cache[k] = new CacheEntry(entry.subject, entry.policy);
        } else if (entry.policy.member) {
          this.cache[k].policy = entry.policy;
        } else {
          delete this.cache[k];
        }
      } else if (entry.opcode.equals(RosterOpcode.SHARE)) {
        if (!this.cache[k]) {
          throw new Error('not a member');
        }
        this.cache[k].share = entry.subject.share;
      } else {
        throw new Error('invalid operation');
      }
    },

    /** Check that the hash and signature on an entry is valid. */
    _checkHashAndSig: function(actor, hash, signed, signature) {
      return Promise.all([
        actor.verify(signature, signed)
          .then(ok => {
            if (!ok) {
              throw new Error('invalid signature on entry');
            }
          }),
        this.lastHash.then(prev => {
          if (!util.bsEqual(prev, hash)) {
            throw new Error('invalid hash in entry');
          }
        })
      ]);
    },

    /** Appends an entry and returns the updated lastHash. */
    _addEntry: function(entry, encoded) {
      // This concurrently:
      //  - encodes the new message and records it
      //  - updates the cache of latest entries

      // Only resolve that promise when both parts of the operation are
      // complete.  That way, any attempt to add to the log (the official
      // transcript) will be assured to get a valid cache state.

      // We have to use the current value and don't await the value that is
      // below, which would setup an unresolvable loop.
      var savedHash = this.lastHash;
      var p = this._validateEntry(entry)
          .then(_ => util.promiseDict({
            logEntry: Promise.resolve(encoded || entry.encode(savedHash)),
            cacheKey: cacheKey(entry.subject)
          })).then(r => {
            this.log.push(r.logEntry);
            this._updateCacheEntry(r.cacheKey, entry);
            return r.logEntry;
          });

      // A lot of the operations that follow depend on knowing the hash of this
      // newly added log entry.  This sets the promise that calculates this
      // value, but doesn't await it.
      this.lastHash = p.then(rawEntry => c.digest(HASH, rawEntry));
      // Set the roster identity, again asynchronously.
      p.then(_ => this._firstEntry(entry));
      return p.then(_ => null);
    },

    /** Decode the buffer into an operation and add it to the log. This rejects
     * if the entry isn't valid.
     */
    _decodeAndAdd: function(parser) {
      var startPosition = parser.position;
      return itemLengths.then(
        lengths => RosterOperation.decode(parser, lengths)
          .then(op => {
            var hash = parser.next(lengths.hash);
            var signedMessage = parser.range(startPosition, parser.position);
            var signature = parser.next(lengths.signature);

            return this._checkHashAndSig(op.actor, hash, signedMessage, signature)
              .then(_ => {
                var encoded = parser.range(startPosition, parser.position);
                return this._addEntry(op, encoded);
              });
          })
      );
    },

    /** Determines if this is the first entry. */
    _firstEntry: function(entry) {
      if (this._resolveIdentity) {
        // Note that we register this roster in the global registry *before*
        // resolving the identity; applications will use the resolution of
        // identity as a signal to start using this roster and they need to be
        // able to rely on a lookup succeeding when they do so.
        var gotId = this._resolveIdentity;
        delete this._resolveIdentity;
        allRosters.register(this, entry.actor)
          .then(_ => gotId(entry.actor.identity));
        return true;
      }
      return false;
    },

    /** Updates all entries in the cache based on the entire transcript. It
     * returns a promise that awaits the process. */
    _rebuildCache: function() {
      // Reset cache state.
      this.cache = {};
      this.lastHash = allZeroHash;
      this.identity = new Promise(r => this._resolveIdentity = r);

      return this.log.reduce(
        (p, buf) => p.then(_ => this._decodeAndAdd(new util.Parser(buf))),
        Promise.resolve()
      );
    }
  };

  /**
   * Creates a new agent roster.  Only the firstUser option is mandatory here.
   * By default the policy is EntityPolicy.ADMIN.
   *
   * This creates a new "change" entry in the log that is signed by a newly
   * created entity.  The keying material for that entity is discarded and never
   * used again.  It is only ever used to establish the roster.
   */
  Roster.create = function(firstUser, policy) {
    policy = policy || EntityPolicy.ADMIN;
    if (!policy.member || !policy.add) {
      throw new Error('firstUser must have "member" and "add" privileges');
    }

    var roster = new Roster();
    return roster.change(new Entity(), firstUser, policy)
      .then(_ => roster);
  };

  function UserRoster(log) {
    Roster.call(this, log);
  }
  UserRoster.prototype = Object.create(Roster.prototype);
  util.mergeDict({
    _checkShare: function() {
      throw new Error('no shares on user roster');
    }
  }, UserRoster.prototype);

  return {
    Roster: Roster,
    UserRoster: UserRoster
  };
});
