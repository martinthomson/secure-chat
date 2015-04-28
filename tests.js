/*global require:false */
var deps = ['require', 'entity', 'policy',
            'roster', 'util', 'test'];
require(deps, function(require) {
  'use strict';

  var run_tests = require('test').run;
  var test = require('test').test;
  var assert = require('test').assert;

  var util = require('util');

  test('base64 array buffer',
       _ => assert.eq(util.base64url.encode(new ArrayBuffer(1)), 'AA'));
  test('base64 array buffer view',
       _ => assert.eq(util.base64url.encode(new Uint8Array(1)), 'AA'));
  test('base64 decode',
       _ => assert.memcmp(util.base64url.decode('AA'), new ArrayBuffer(1)));
  test('divide array buffer', _ => {
    var divs = util.bsDivide(new ArrayBuffer(10), 3);
    assert.eq(divs.length, 4);
    assert.ok(divs.slice(0, 3).every(d => d.byteLength === 3));
    assert.ok(divs[3].byteLength, 1);
    return divs;
  });
  test('divide array buffer view', _ => {
    var divs = util.bsDivide(new ArrayBuffer(10), 5);
    assert.eq(divs.length, 2);
    assert.ok(divs.every(d => d.byteLength === 5));
    return divs;
  });

  var EntityPolicy = require('policy');

  var policyOrder = [ EntityPolicy.ADMIN, EntityPolicy.USER,
                      EntityPolicy.OBSERVER, EntityPolicy.NONE ];
  test('policy pecking order', _ => {
    return policyOrder.every((superior, i) => {
      return policyOrder.slice(i).every(
        inferior => superior.subsumes(inferior) ||
          assert.failv('not subsumes', [superior, inferior])
      );
    });
  });
  test('policy encode/decode', _ => {
    return policyOrder.every(input => {
      var output = EntityPolicy.decode(input.encode());
      return assert.ok(input.equals(output));
    });
  });
  test('policy can add', _ => {
    return policyOrder.every((high, i) => {
      return policyOrder.slice(i + 1)
        .every(low => EntityPolicy.USER.canChange(low, high));
    });
  });
  test('policy can remove', _ => {
    var actor = new EntityPolicy(['member', 'remove']);
    return policyOrder.every((high, i) => {
      return policyOrder.slice(i + 1)
        .every(low => actor.canChange(high, low));
    });
  });
  test('policy can change', _ => {
    var allPolicies = policyOrder.concat([
      ['add'], ['add', 'remove'], ['remove'], ['member', 'remove']
    ].map(privs => new EntityPolicy(privs)));
    return allPolicies.every(a => {
      return allPolicies.filter(b => b !== a)
        .every(b => EntityPolicy.ADMIN.canChange(a, b));
    });
  });

  var Entity = require('entity').Entity;

  test('entity identity', _ => new Entity().identity);
  test('entity share', _ => new Entity().share);
  test('sign and verify', _ => {
    var e = new Entity();
    var msg = new Uint8Array(1);
    return e.sign(msg)
      .then(sig => e.verify(sig, msg))
      .then(assert.ok);
  });

  var Roster = require('roster').Roster;
  var creator = new Entity();
  var user = new Entity();

  test('roster identity matches creator identity', _ => {
    return Roster.create(creator)
      .then(roster => util.promiseDict({
        roster: roster.identity,
        creator: creator.identity
      })).then(r => assert.memcmp(r.roster, r.creator));
  });
  test('create roster and find creator', _ => {
    return Roster.create(creator)
      .then(roster => roster.find(creator))
      .then(found => util.promiseDict({
        found: found.identity,
        creator: creator.identity
      })).then(r => assert.memcmp(r.found, r.creator));
  });
  test('create roster and find first', _ => {
    return Roster.create(creator, user)
      .then(roster => roster.find(user))
      .then(found => util.promiseDict({
        found: found.identity,
        user: user.identity
      })).then(ids => assert.memcmp(ids.found, ids.user));
  });
  test('creator can leave', _ => {
    return Roster.create(creator)
      .then(roster => roster.change(creator, creator, EntityPolicy.NONE));
  });
  test('creator can\'t remove first user', _ => {
    return Roster.create(creator, user)
      .then(roster => roster.change(creator, user, EntityPolicy.NONE))
      .then(_ => assert.fail('should not succeed'),_ => true);
  });
  test('policy default is admin', _ => {
    return Roster.create(user)
      .then(roster => roster.findPolicy(user))
      .then(policy =>
            policy.equals(EntityPolicy.ADMIN) ||
            assert.failv('not admin', [policy]));
  });
  test('policy for absent user is none', _ => {
    return Roster.create(user)
      .then(roster => roster.findPolicy(new Entity()))
      .then(policy => policy.equals(EntityPolicy.NONE) ||
            assert.failv('not none', [policy]));
  });
  test('add user and change their policy', _ => {
    return Roster.create(creator)
      .then(roster => {
        // This produces an incremental transition from
        // observer to admin and then back to none.
        var policies = [].concat(policyOrder);
        policies.reverse();
        policies = [].concat(policies.slice(1), policyOrder.slice(1));
        return policies.reduce(
          (p, policy) => p.then(_ => roster.change(creator, user, policy))
            .then(_ => roster.findPolicy(user))
            .then(found => assert.eq(found, policy)),
          Promise.resolve()
        );
      });
  });
  test('user can add after creator leaves', _ => {
    var third = new Entity();
    return Roster.create(creator)
      .then(
        roster => roster.change(creator, user, EntityPolicy.USER)
          .then(_ => roster.change(creator, creator, EntityPolicy.NONE))
          .then(_ => roster.change(user, third, EntityPolicy.USER))
      );
  });
  test('user can advertise share', _ => {
    return Roster.create(creator, user)
      .then(
        roster => roster.share(user)
          .then(_ => roster.findShare(user))
          .then(found => util.promiseDict({
            found: found,
            user: user.share
          }))
          .then(r => assert.memcmp(r.found, r.user))
      );
  });
  /** Creates a roster with a creator-admin and one of each other named policy
   * type.  Returns a map with two keys: users and roster. All the users have
   * their shares advertised. */
  var createTestRoster = _ => {
    return Roster.create(creator)
      .then(roster => {
        var policies = ['ADMIN', 'USER', 'OBSERVER'];
        var users = policies.reduce(
          (userMap, policy) => {
            userMap[policy] = new Entity();
            return userMap;
          }, {});
        return Promise.all(
          policies.map(
            policy => roster.change(creator, users[policy],
                                    EntityPolicy[policy])
              .then(_ => roster.share(users[policy]))
          )
        ).then(_ => {
          return { roster: roster, users: users };
        });
      });
  };
  test('encode and decode', _ => {
    return createTestRoster().then(result => {
      // Encode and decode the resulting roster.
      var encoded = result.roster.encode();
      var decoded = new Roster([]);
      return decoded.decode(encoded)
        .then(_ => {
          // Get the set of users that we added to the original.
          var users = Object.keys(result.users)
              .map(k => result.users[k]);
          // Find all of them to check that they were copied over.
          return Promise.all(
            users.map(u => decoded.find(u))
          ).then(found => found.map(assert.ok));
        });
    });
  });

  test('get all shares', _ => {
    return createTestRoster().then(result => {
      return util.promiseDict({
        stored: result.roster.allShares(),
        expected: Promise.all(
          Object.keys(result.users)
            .map(k => result.users[k].share)
        )
      }).then(
        r => assert.ok(r.expected.every(
          toFind => r.stored.some(
            candidate => util.bsEqual(candidate, toFind)
          )
        ))
      );
    });
  });

  run_tests();
});
