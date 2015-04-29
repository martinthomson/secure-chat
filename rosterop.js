define(['require', 'util', 'entity', 'policy'], function(require) {
  'use strict';

  var util = require('util');
  var EntityPolicy = require('policy');
  var PublicEntity = require('entity').PublicEntity;

  function RosterOpcode(op) {
    this.opcode = op;
  }
  RosterOpcode.prototype = {
    encode: function() {
      return new Uint8Array([this.opcode]);
    },
    equals: function(other) {
      return other instanceof RosterOpcode &&
        this.opcode === other.opcode;
    },
    toString: function() {
      return 'RosterOpcode(' + this.opcode + ')';
    }
  };
  RosterOpcode.decode = function(buf) {
    return new RosterOpcode(new Uint8Array(buf)[0]);
  };
  RosterOpcode.CHANGE = new RosterOpcode(0);
  RosterOpcode.SHARE = new RosterOpcode(1);
  RosterOpcode.CHANGE_ROSTER = new RosterOpcode(2);

  /**
   * The base implementation of an operation on the roster.
   */
  function RosterOperation(actor, subject) {
    this.actor = actor;
    this.subject = subject;
  }

  RosterOperation.prototype = {
    _encodeParts: function() {
      throw new Error('not implemented');
    },
    /** Encodes this.  This takes a promise to the hash of the previous entry. */
    encode: function(lastEntryHash) {
      var pieces = [].concat(
        this.opcode.encode(),
        this._encodeParts(),
        this.actor.identity,
        lastEntryHash
      );

      return Promise.all(pieces)
        .then(encodedPieces => {
          var msg = util.bsConcat(encodedPieces);
          return this.actor.sign(msg)
            .then(sig => {
              return util.bsConcat([msg, sig]);
            });
        });
    }
  };

  function ChangeOperation(actor, subject, policy) {
    RosterOperation.call(this, actor, subject);
    this.opcode = RosterOpcode.CHANGE;
    this.policy = policy;
  }
  ChangeOperation.prototype = util.mergeDict({
    _encodeParts: function() {
      return [ this.subject.identity, this.policy.encode() ];
    }
  }, Object.create(RosterOperation.prototype));

  function ShareOperation(actor) {
    RosterOperation.call(this, actor, actor);
    this.opcode = RosterOpcode.SHARE;
  }
  ShareOperation.prototype = util.mergeDict({
    _encodeParts: function() {
      return [ this.subject.encodeShare() ];
    }
  }, Object.create(RosterOperation.prototype));

  /** For a user roster, changes need to identify the actor AND the roster that
   * they are acting for. The roster is used to determine whether the action is
   * permitted. The actor is used to provide the signing public key; the actor
   * also needs to be a member on the roster. */
  function RosterChangeOperation(actor, actorRoster, subject, policy) {
    ChangeOperation.call(this, actor, subject, policy);
    this.opcode = RosterOpcode.CHANGE_ROSTER;
    this.actorRoster = actorRoster;
  }
  RosterChangeOperation.prototype = util.mergeDict({
    _encodeParts: function() {
      var base = ChangeOperation.prototype._encodeParts.call(this);
      if (this.actorRoster) {
        return base.concat([ this.actorRoster.identity ]);
      }
      return base.concat([ this.actor.identity
                           .then(id => new Uint8Array(id.byteLength)) ]);
    }
  }, Object.create(ChangeOperation.prototype));


  RosterOperation.decode = function(parser, lengths, allRosters) {
    var opcode = RosterOpcode.decode(parser.next(lengths.opcode));
    var subject, actor, policy;

    if (opcode.equals(RosterOpcode.CHANGE)) {
      subject = new PublicEntity(parser.next(lengths.identifier));
      policy = EntityPolicy.decode(parser.next(lengths.policy));
      actor = new PublicEntity(parser.next(lengths.identifier));
      return Promise.resolve(new ChangeOperation(actor, subject, policy));
    }
    if (opcode.equals(RosterOpcode.SHARE)) {
      var share = parser.next(lengths.share);
      actor = new PublicEntity(parser.next(lengths.identifier), share);
      return Promise.resolve(new ShareOperation(actor));
    }
    if (opcode.equals(RosterOpcode.CHANGE_ROSTER)) {
      subject = allRosters.lookup(parser.next(lengths.identifier));
      policy = EntityPolicy.decode(parser.next(lengths.policy));
      var actorRoster = allRosters.lookup(parser.next(lengths.identifier));
      actor = new PublicEntity(parser.next(lengths.identifier));
      return util.promiseDict({
        subject: subject,
        actorRoster: actorRoster
      }).then(r => new RosterChangeOperation(actor, r.actorRoster,
                                             r.subject, policy));
    }
    return Promise.reject(new Error('invalid operation: ' + opcode.opcode));
  };

  return {
    ChangeOperation: ChangeOperation,
    RosterChangeOperation: RosterChangeOperation,
    RosterOpcode: RosterOpcode,
    RosterOperation: RosterOperation,
    ShareOperation: ShareOperation
  };
});
