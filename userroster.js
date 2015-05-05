var reqs = ['require', 'util', 'entity', 'policy', 'rosterop', 'roster'];
define(reqs, function(require) {
  'use strict';

  var util = require('util');
  var EntityPolicy = require('policy');
  var Entity = require('entity').Entity;
  var RosterOpcode = require('rosterop').RosterOpcode;
  var RosterChangeOperation = require('rosterop').RosterChangeOperation;
  var Roster = require('roster');

  /** Used internally by the roster to track the status of entities in the
   * roster */
  function UserCacheEntry(roster, policy) {
    this.roster = roster;
    this.policy = policy;
  }

  function UserRoster() {
    Roster.call(this);
  }
  UserRoster.prototype = util.mergeDict({

    /** Enact a change in policy for the subject, triggered by actor.  This will
     * reject if the change is not permitted.
     */
    change: function(actor, actorRoster, subject, policy) {
      return this._addEntry(new RosterChangeOperation(actor, actorRoster,
                                                      subject, policy));
    },

    /** Returns all the user rosters that are a member of this roster. */
    users: function() {
      return Object.keys(this._cache)
        .map(k => this._cache[k].roster);
    },

    /** Returns all the agents that are part of this roster.  This traverses all
     * the rosters that this roster includes as a member to retrieve this
     * information. */
    agents: function() {
      return this.users().map(r => r.agents())
        .reduce((all, member) => all.concat(member), []);
    },

    /** Enacts the change in `entry` on the cache. */
    _updateCacheEntry: function(k, entry) {
      if (entry.opcode.equals(RosterOpcode.CHANGE_ROSTER)) {
        if (!this._cache[k]) {
          this._cache[k] = new UserCacheEntry(entry.subject, entry.policy);
        } else if (entry.policy.member) {
          this._cache[k].policy = entry.policy;
        } else {
          delete this._cache[k];
        }
      } else {
        throw new Error('invalid operation on user roster: ' + entry.opcode);
      }
    },

    /** Check that the addition of a roster is OK. */
    _checkRosterChange: function(actor, actorRoster, subject, proposed) {
      return Promise.all([
        this._checkChange(actorRoster, subject, proposed),
        actorRoster.find(actor)
          .then(found => {
            if (!found) {
              throw new Error('actor is not in advertised roster');
            }
          })
      ]);
    },

    /** Determines if the given change is acceptable. */
    _validateEntry: function(entry) {
      if (entry.opcode.equals(RosterOpcode.CHANGE_ROSTER)) {
        // If this is the first entry, no checks.
        if (this._logIsEmpty()) {
          return Promise.resolve();
        }
        return this._checkRosterChange(entry.actor, entry.actorRoster,
                                       entry.subject, entry.policy);
      }
      return Promise.reject(new Error('invalid opcode for user roster: ' +
                                      entry.opcode));
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
  UserRoster.create = function(firstUserRoster, policy) {
    policy = policy || EntityPolicy.ADMIN;
    if (!policy.member || !policy.add) {
      throw new Error('firstUserRoster must have "member" and "add" privileges');
    }

    var roster = new UserRoster();
    // Ordinarily the null would be forbidden, but the first entry is special in
    // that regard.
    return roster.change(new Entity(), null, firstUserRoster, policy)
      .then(_ => roster);
  };

  return UserRoster;
});
