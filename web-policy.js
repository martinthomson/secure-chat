define(['require', 'web-util'], function(require) {
  'use strict';

  var util = require('web-util');

  /**
   * An entity policy identifies the set of attributes for a roster participant.
   * This doesn't include policy with respect to the *use* of the roster, it
   * only describes what actions the entity can take with respect to the roster
   * itself.
   *
   * The policy is dictionary of boolean flags that describe an entity's
   * relationship to the roster:
   *
   * - member: whether the entity is considered to be a member
   *
   * - add: whether the entity can set a policy flag to true on other entities;
   *        if it can, then it can set any policy flag that it has itself
   *
   * - remove: whether the entity can remove policy bits on other members; if it
   *           can, then it can clear any bit
   *
   * All users are assumed to be able to modify their own status.
   */
  function EntityPolicy(version, policy) {
    this.version = version;
    this.policy = policy;
  }
  EntityPolicy.prototype = {
    /** Turn into an Uint8Array. */
    encode: function() {
      return Uint8Array.from([
        this.version << 6 |
          (this.policy.member ? (1 << 5) : 0) |
          (this.policy.add ? (1 << 4) : 0) |
          (this.policy.remove ? (1 << 3) : 0)
      ]);
    },

    /** Determines if this policy contains a superset of the privileges that are
     * in the other policy.  This is used to determine if the user with this
     * policy can set this policy on others. */
    subsumes: function(other) {
      if (this.version !== other.version) {
        return false;
      }
      return Object.keys(other.policy)
        .every(k => (this.policy[k] || !other.policy[k]));
    },

    /** Simple comparator */
    equals: function(other) {
      if (this.version !== other.version) {
        return false;
      }
      var eq = k => this.policy[k] === other.policy[k];
      return Object.keys(other.policy).every(eq) &&
        Object.keys(this.policy).every(eq);
    },

    /** Returns true if the change to another entity is permitted.  This first
     * checks is the current policy subsumes the new policy: we can't permit a
     * member to add properties that they do not have themselves.  Then it
     * checks that the changes are legal.
     */
    canChange: function(oldPolicy, newPolicy) {
      return this.subsumes(newPolicy) && (
        (this.policy.add && this.policy.remove) ||
          (this.policy.remove && oldPolicy.subsumes(newPolicy)) ||
          (this.policy.add && newPolicy.subsumes(oldPolicy))
      );
    }
  };

  EntityPolicy.decode = buf => {
    var v = toUint8Array(buf)[0];
    return new EntityPolicy(v >>> 6, {
      member: v & (1 << 5),
      add: v & (1 << 4),
      remove: v & (1 << 3)
    });
  };

  EntityPolicy.ADMIN =
    new EntityPolicy(0, { member: true, add: true, change: true });
  EntityPolicy.USER =
    new EntityPolicy(0, { member: true, add: true, change: false });
  EntityPolicy.OBSERVER =
    new EntityPolicy(0, { member: true, add: false, change: false });
  EntityPolicy.NONE = new EntityPolicy(0, { });

  return EntityPolicy;
});
