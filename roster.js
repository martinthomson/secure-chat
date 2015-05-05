define(['require', 'util', 'entity', 'policy', 'rosterop'], function(require) {
  'use strict';

  var c = crypto.subtle;
  var util = require('util');
  var EntityPolicy = require('policy');
  var PublicEntity = require('entity').PublicEntity;
  var RosterOperation = require('rosterop').RosterOperation;
  var RosterOpcode = require('rosterop').RosterOpcode;

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
      return cacheKey(entity).then(k => this._cache[k]);
    },

    /** Find the cached policy for the given entity.  This will resolve
     * successfully with EntityPolicy.NONE if there are no entries. */
    findPolicy: function(entity) {
      return this.find(entity).then(v => v ? v.policy : EntityPolicy.NONE);
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

    _updateCacheEntry: function() {
      throw new Error('_updateCacheEntry not implemented');
    },

    _validateEntry: function() {
      throw new Error('_validateEntry not implemented');
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

    /** Check that the hash and signature on an entry is valid. */
    _checkHashAndSig: function(actor, hash, signed, signature) {
      return Promise.all([
        actor.verify(signature, signed)
          .then(ok => {
            if (!ok) {
              throw new Error('invalid signature on entry');
            }
          }),
        this._lastHash.then(prev => {
          if (!util.bsEqual(prev, hash)) {
            throw new Error('invalid hash in entry');
          }
        })
      ]);
    },

    /** Appends an entry and returns the encoded entry that it created. */
    _addEntry: function(entry, encoded) {
      // This concurrently:
      //  - encodes the new message and records it
      //  - updates the cache of latest entries

      // Only resolve that promise when both parts of the operation are
      // complete.  That way, any attempt to add to the log (the official
      // transcript) will be assured to get a valid cache state.

      // We have to save the current value so that we don't await the amended
      // value below, which would create a deadlock.
      var savedHash = this._lastHash;
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
      // value, but doesn't await it.  This promise is used to ensure that
      // operations are properly sequenced.
      this._lastHash = p.then(rawEntry => c.digest(HASH, rawEntry));
      // Set the roster identity based on the first log entry asynchronously.
      if (this._logIsEmpty()) {
        p.then(_ => this._firstEntry(entry));
      }
      return p;
    },

    /** Decode the buffer into an operation and add it to the log. This rejects
     * if the entry isn't valid.
     */
    _decodeAndAdd: function(parser) {
      var startPosition = parser.mark();
      return itemLengths.then(
        lengths => RosterOperation.decode(parser, lengths, Roster._allRosters)
          .then(op => {
            var hash = parser.next(lengths.hash);
            var signedMessage = parser.marked(startPosition);
            var signature = parser.next(lengths.signature);

            return this._checkHashAndSig(op.actor, hash, signedMessage, signature)
              .then(_ => {
                var encoded = parser.marked(startPosition);
                return this._addEntry(op, encoded);
              });
          })
      );
    },

    /** Returns true if there are no entries. */
    _logIsEmpty: function() {
      return this.log.length === 0;
    },

    /** Determines if this is the first entry. */
    _firstEntry: function(entry) {
      if (!this._resolveIdentity) {
        throw new Error('unable to resolve the first identity');
      }
      // Note that we register this roster in the global registry *before*
      // resolving the identity; applications will use the resolution of
      // identity as a signal to start using this roster and they need to be
      // able to rely on a lookup succeeding when they do so.
      var gotId = this._resolveIdentity;
      delete this._resolveIdentity;
      Roster._allRosters.register(this, entry.actor)
        .then(_ => gotId(entry.actor.identity));
    },

    /** Updates all entries in the cache based on the entire transcript. It
     * returns a promise that awaits the process. */
    _rebuildCache: function() {
      // Reset cache state.
      this._cache = {};
      this._lastHash = allZeroHash;
      this.identity = new Promise(r => this._resolveIdentity = r);

      return this.log.reduce(
        (p, buf) => p.then(_ => this._decodeAndAdd(new util.Parser(buf))),
        Promise.resolve()
      );
    }
  };
  Roster._allRosters = new AllRosters();
  Roster.findRoster = function(entity) {
    return Roster._allRosters.lookup(entity);
  };

  return Roster;
});
