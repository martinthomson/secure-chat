define(['require', 'util'], function(require) {
  'use strict';

  var util = require('util');

  /**
   * An entity policy identifies the set of attributes for a roster participant.
   * This doesn't include policy with respect to the *use* of the roster, it
   * only describes what actions the entity can take with respect to the roster
   * itself.
   *
   * The policy is list of strings that identify an entity's privileges in the
   * roster:
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
  function EntityPolicy(privileges) {
    privileges.forEach(priv => this[priv] = true);
  }

  EntityPolicy.prototype = {
    /** Turn into an Uint8Array. */
    encode: function() {
      return new Uint8Array([
        (this.member ? (1 << 0) : 0) |
          (this.add ? (1 << 1) : 0) |
          (this.remove ? (1 << 2) : 0)
      ]);
    },

    /** Determines if this policy contains a superset of the privileges that are
     * in the other policy.  This is used to determine if the user with this
     * policy can set this policy on others. */
    subsumes: function(other) {
      return Object.keys(other)
        .every(k => (this[k] || !other[k]));
    },

    /** Simple comparator */
    equals: function(other) {
      // Note: use boolean coercion explicitly
      // to allow undefined to compare equal to false
      var eq = k => !this[k] === !other[k]; // jshint ignore:line
      return (other instanceof EntityPolicy) &&
        Object.keys(other).every(eq) &&
        Object.keys(this).every(eq);
    },

    /** Returns true if an actor with this policy is permitted to make the
     * proposed change to another entity.
     */
    canChange: function(oldPolicy, newPolicy) {
      // No lame changes allowed.
      return !newPolicy.equals(oldPolicy) &&
        // Check if the current policy subsumes the new policy: don't allow
        // adding add privileges that members don't have themselves.
        this.subsumes(newPolicy) && (
          // If you can both add or remove, no more checks needed.
          (this.add && this.remove) ||
          // If you can only remove, then you need to remove.
          (this.remove && oldPolicy.subsumes(newPolicy)) ||
          // If you can add, then you have to be granting privileges and you
          // must grant at least member privilege.
          (this.add && newPolicy.subsumes(oldPolicy) &&
           newPolicy.member)
        );
    },

    toJSON: function() {
      return Object.keys(this).filter(k => this[k]);
    },
    toString: function() {
      return JSON.stringify(this);
    }
  };

  EntityPolicy.decode = buf => {
    var v = new Uint8Array(buf)[0];
    if ((v >>> 6) !== 0) {
      throw new Error('unsupported policy version');
    }
    return util.mergeDict({
      member: !!(v & 1 << 0),
      add: !!(v & (1 << 1)),
      remove: !!(v & (1 << 2))
    }, new EntityPolicy([]));
  };

  EntityPolicy.ADMIN = new EntityPolicy(['member', 'add', 'remove']);
  EntityPolicy.USER = new EntityPolicy(['member', 'add']);
  EntityPolicy.OBSERVER = new EntityPolicy(['member']);
  EntityPolicy.NONE = new EntityPolicy([]);

  return EntityPolicy;
});
