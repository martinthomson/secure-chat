define(['require', 'util', 'entity', 'policy', 'rosterop', 'roster'], function(require) {
  'use strict';

  var util = require('util');
  var EntityPolicy = require('policy');
  var PublicEntity = require('entity').PublicEntity;
  var Entity = require('entity').Entity;
  var RosterOpcode = require('rosterop').RosterOpcode;
  var ChangeOperation = require('rosterop').ChangeOperation;
  var ShareOperation = require('rosterop').ShareOperation;
  var Roster = require('roster');

  /** Used internally by the roster to track the status of entities in the roster */
  function AgentCacheEntry(subject, policy) {
    PublicEntity.call(this, subject.identity, subject.share);
    this.policy = policy;
  }
  AgentCacheEntry.prototype = Object.create(PublicEntity.prototype);

  function AgentRoster() {
    Roster.call(this);
  }
  AgentRoster.prototype = util.mergeDict({

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

    /** Find the cached share for the given entity.  This will resolve
     * successfully with null if there are no entries. */
    findShare: function(entity) {
      return this.find(entity).then(v => v ? v.share : null);
    },

    /** Returns an array of all the active members in the roster.  That is, all
     * those that have provided shares. */
    participants: function() {
      return Object.keys(this._cache)
        .map(k => this._cache[k])
        .filter(e => !!e.share);
    },

    /** Enacts the change in `entry` on the cache. */
    _updateCacheEntry: function(k, entry) {
      if (entry.opcode.equals(RosterOpcode.CHANGE)) {
        if (!this._cache[k]) {
          this._cache[k] = new AgentCacheEntry(entry.subject, entry.policy);
        } else if (entry.policy.member) {
          this._cache[k].policy = entry.policy;
        } else {
          delete this._cache[k];
        }
      } else if (entry.opcode.equals(RosterOpcode.SHARE)) {
        if (!this._cache[k]) {
          throw new Error('not a member');
        }
        this._cache[k].share = entry.subject.share;
      } else {
        throw new Error('invalid operation on agent roster');
      }
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
      if (entry.opcode.equals(RosterOpcode.CHANGE)) {
        // If this is the first entry, no checks.  A share operation will cause
        // the roster to become busted, so don't permit that.
        if (this._logIsEmpty()) {
          return Promise.resolve();
        }
        return this._checkChange(entry.actor, entry.subject, entry.policy);
      }
      if (entry.opcode.equals(RosterOpcode.SHARE)) {
        return this._checkShare(entry.subject);
      }
      return Promise.reject(new Error('invalid opcode for agent roster'));
    }
  }, Object.create(Roster.prototype));

  /**
   * Creates a new agent roster.  Only the firstUser option is mandatory here.
   * By default the policy is EntityPolicy.ADMIN.
   *
   * This creates a new "change" entry in the log that is signed by a newly
   * created entity.  The keying material for that entity is discarded and never
   * used again.  It is only ever used to establish the roster.
   */
  AgentRoster.create = function(firstUser, policy) {
    policy = policy || EntityPolicy.ADMIN;
    if (!policy.member || !policy.add) {
      throw new Error('firstUser must have "member" and "add" privileges');
    }

    var roster = new AgentRoster();
    return roster.change(new Entity(), firstUser, policy)
      .then(_ => roster.share(firstUser))
      .then(_ => roster);
  };

  return AgentRoster;
});
