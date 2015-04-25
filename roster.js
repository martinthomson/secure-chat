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


  /**
   * Create a new roster entry.
   *
   * @policy an EntityPolicy instance
   * @subject the entity that is being changed; a PublicEntity.
   * @actor the entity generating the entry; if this.encode() is needed, this
   *        will need to be an instance of Entity; otherwise PublicEntity is OK.
   * @hash a promise to a hash of the current last entry in the log
   */
  function RosterEntry(policy, subject, actor) {
    this.policy = policy;
    this.subject = subject;
    this.actor = actor;
  }
  RosterEntry.prototype = {
    /** Encodes this, taking a promise to the hash of the last value */
    encode: function(lastEntryHash) {
      return Promise.all([this.policy.encode(), this.subject.encode(),
                          this.actor.identity, lastEntryHash])
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
      var pSubject = PublicEntity.decode(nextChunk(lengths.entity));
      var actor = new PublicEntity(nextChunk(lengths.identifier));
      var hash = nextChunk(lengths.hash);
      var signatureMessage = buf.slice(0, pos);
      var signature = nextChunk(lengths.signature);

      return util.promiseDict({
        subject: pSubject,
        verify: actor.verify(signature, signatureMessage)
          .then(ok => {
            if (!ok) {
              throw new Error('invalid signature on entry');
            }
          }),
        hashCheck: (lastHash || allZeroHash).then(h => {
          if (!util.bsEqual(h, hash)) {
            throw new Error('invalid hash in entry');
          }
        })
      }).then(r => new RosterEntry(policy, r.subject, actor));
    });
  };

  function AgentRoster(initialEntry) {
    this.entries = [initialEntry];
    this.lastHash = c.digest(HASH, initialEntry);
  }
  AgentRoster.prototype = {
    get last() {
      return this.entries[this.entries.length - 1];
    },

    getCachedPolicy: function(entity) {
      return entity.identifier.then(id => {
        return this.cache[util.base64url.encode(id)];
      });
    },

    /** Takes an encoded entry (ebuf) and a promise for the hash of the last
     * message (lastHash) and updates the cache based on that information.  This
     * rejects if the entry isn't valid (see RosterEntry.decode). If lastHash is
     * unset, then the entry is the first and the change is automatically
     * permitted. */
    _updateCacheEntry: function(ebuf, lastHash) {
      return RosterEntry.decode(ebuf, lastHash)
        .then(entry => {
          var check = Promise.resolve();
          if (lastHash) {
            check = check.then(_ => this._checkChange(entry.actor, entry.subject, entry.policy));
          }
          return check.then(_ => AgentRoster._cacheKey(entry.subject))
            .then(k => this.cache[k] = entry);
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
            entry: this._updateCacheEntry(ebuf, lastHash),
            hash: c.digest(HASH, ebuf)
          }).then(result => result.hash);
        }, null);
    },

    /** Find a cached entry for the given entity.  This will resolve
     * successfully to undefined if there are no entries. */
    find: function(entity) {
      return AgentRoster._cacheKey(entity)
        .then(k => this.cache[k]);
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

    /** Enact a change in policy for the subject, triggered by actor.  This will
     * reject if the change is not permitted.
     */
    change: function(actor, subject, policy) {
      return this._checkChange(actor, subject, policy)
        .then(_ => {
          var entry = new RosterEntry(policy, subject, actor);

          // Note that only one action can be outstanding on the log at a time.
          // This uses `this.lastHash` as the interlock on operations that
          // affect the log.  Thus, we need to update lastHash as soon as we
          // decide to commit to any change so that subsequent calls are
          // enqueued behind this one.

          // This concurrently:
          //  - encodes the new message and records it
          //  - updates the cache of latest entries

          // Important Note: If anything here fails for any reason, the log can
          // no longer be added to.  All calls to modify the log depend on the
          // value of the last hash being valid.  It *might* be possible to back
          // out a failed change, but that would need careful consideration.
          return this.lastHash = util.promiseDict({
            hash: entry.encode(this.lastHash)
              .then(encoded => {
                this.entries.push(encoded);
                return c.digest(HASH, encoded);
              }),
            update: AgentRoster._cacheKey(subject)
              .then(k => this.cache[k] = entry)
          }).then(r => r.hash);
        });
    },

    toJSON: function() {
      return this.entries.map(util.bsHex);
    }
  };
  /** A simple helper that determines the cache key for an entity. */
  AgentRoster._cacheKey = function(entity) {
    return entity.identity.then(id => util.base64url.encode(id));
  };
  /**
   * Creates a new roster.  You can set a different policy here, but
   */
  AgentRoster.create = function(creator, policy) {
    policy = policy || EntityPolicy.ADMIN;
    if (!policy.member || !policy.add) {
      throw new Error('creator must be a member that can add others');
    }
    var entry = new RosterEntry(policy, creator, creator);
    return entry.encode(allZeroHash)
      .then(encoded => new AgentRoster(encoded))
      .then(roster => {
        return roster.rebuildCache().then(_ => roster);
      });
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
