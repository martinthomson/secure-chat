/*global require:false */
var deps = ['require', 'util', 'entity', 'policy',
            'agentroster', 'userroster', 'chatlog', 'test'];
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

  var AgentRoster = require('agentroster');
  var admin = new Entity();
  var user = new Entity();

  test('roster identity does not matches first user identity', _ => {
    return AgentRoster.create(user)
      .then(roster => util.promiseDict({
        roster: roster.identity,
        user: user.identity
      })).then(r => assert.notok(util.bsEqual(r.roster, r.user)));
  });
  test('create roster and find user', _ => {
    return AgentRoster.create(user)
      .then(roster => roster.find(user))
      .then(found => util.promiseDict({
        found: found.identity,
        user: user.identity
      })).then(r => assert.memcmp(r.found, r.user));
  });
  test('user can leave', _ => {
    return AgentRoster.create(user)
      .then(roster => roster.change(user, user, EntityPolicy.NONE));
  });
  test('other user can\'t remove first user', _ => {
    return AgentRoster.create(user)
      .then(roster => roster.change(new Entity(), user, EntityPolicy.NONE))
      .then(_ => assert.fail('should not succeed'), _ => true);
  });
  test('policy default is admin', _ => {
    return AgentRoster.create(user)
      .then(roster => roster.findPolicy(user))
      .then(policy =>
            policy.equals(EntityPolicy.ADMIN) ||
            assert.failv('not admin', [policy]));
  });
  test('policy for absent user is none', _ => {
    return AgentRoster.create(user)
      .then(roster => roster.findPolicy(new Entity()))
      .then(policy => policy.equals(EntityPolicy.NONE) ||
            assert.failv('not none', [policy]));
  });
  test('add user and change their policy', _ => {
    return AgentRoster.create(admin)
      .then(roster => {
        // This produces an incremental transition from
        // observer to admin and then back to none.
        var policies = [].concat(policyOrder);
        policies.reverse();
        policies = [].concat(policies.slice(1), policyOrder.slice(1));
        return policies.reduce(
          (p, policy) => p.then(_ => roster.change(admin, user, policy))
            .then(_ => roster.findPolicy(user))
            .then(found => assert.eq(found, policy)),
          Promise.resolve()
        );
      });
  });
  test('user can add after creator leaves', _ => {
    return AgentRoster.create(admin)
      .then(
        roster => roster.change(admin, user, EntityPolicy.USER)
          .then(_ => roster.change(admin, admin, EntityPolicy.NONE))
          .then(_ => roster.change(user, new Entity(), EntityPolicy.USER))
      );
  });
  test('user can advertise share', _ => {
    return AgentRoster.create(user)
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
   * type.  Returns a map with two keys: agents and roster. All the agents have
   * their shares advertised. */
  var createTestAgentRoster = _ => {
    return AgentRoster.create(admin)
      .then(roster => {
        var policies = ['ADMIN', 'USER', 'OBSERVER'];
        var agents = policies.reduce(
          (userMap, policy) => {
            userMap[policy] = new Entity();
            return userMap;
          }, {});
        return Promise.all(
          policies.map(
            policy => roster.change(admin, agents[policy],
                                    EntityPolicy[policy])
              .then(_ => roster.share(agents[policy]))
          )
        ).then(_ => {
          return { roster: roster, agents: agents };
        });
      });
  };
  test('encode and decode', _ => {
    return createTestAgentRoster().then(result => {
      // Encode and decode the resulting roster.
      var encoded = result.roster.encode();
      var decoded = new AgentRoster([]);
      return decoded.decode(encoded)
        .then(_ => {
          // Get the set of user tshat we added to the original.
          var agents = Object.keys(result.agents)
              .map(k => result.agents[k]);
          // Find all of them to check that they were copied over.
          return Promise.all(
            agents.map(u => decoded.find(u))
          ).then(found => found.map(assert.ok));
        });
    });
  });

  test('get all shares', _ => {
    return createTestAgentRoster().then(result => util.promiseDict({
      stored: Promise.all(result.roster.members()
                          .map(member => member.encodeShare())),
      expected: Promise.all(
        [ admin ].concat(
          Object.keys(result.agents)
            .map(k => result.agents[k])
        ).map(u => u.encodeShare())
      )
    })).then(r => assert.ok(
      util.arraySetEquals(r.stored, r.expected, util.bsEqual)
    ));
  });

  var UserRoster = require('userroster');

  test('create user roster', _ => {
    return createTestAgentRoster()
      .then(result => UserRoster.create(result.roster));
  });

  var createTestUserRoster = _ => {
    return Promise.all([createTestAgentRoster(),
                        createTestAgentRoster(),
                        createTestAgentRoster()])
      .then(users => util.promiseDict({
        roster:
        UserRoster.create(users[0].roster).then(
          userRoster => Promise.all(users.slice(1).map(
            user => userRoster.change(users[0].agents.USER, users[0].roster,
                                      user.roster, EntityPolicy.USER)
          )).then(_ => userRoster)
        ),

        users: users.map(x => x.roster),

        agents: users.reduce(
          (allAgents, user) => {
            var agents = Object.keys(user.agents)
                .map(k => user.agents[k]);
            return allAgents.concat(agents);
          },
          [ admin ]
        )
      }));
  };

  test('create user roster and get all shares', _ => {
    return createTestUserRoster()
      .then(r => util.promiseDict({
        rosterShares:  Promise.all(
          r.roster.members()
            .map(member => member.encodeShare())
        ),

        expectedShares: Promise.all(
          r.agents.map(agent => agent.encodeShare())
        )
      })).then(r => assert.ok(
        util.arraySetEquals(r.rosterShares, r.expectedShares,
                            util.bsEqual)
      ));
  });

  var ChatKey = require('chatlog').ChatKey;

  test('create a chat key', _ => {
    var rand = crypto.getRandomValues(new Uint8Array(16));
    var key = new ChatKey(new Entity(), rand);
    return key.identity;
  });

  var ChatLog = require('chatlog').ChatLog;

  test('create a chat log', _ => {
    return createTestUserRoster()
      .then(r => {
        var chat = new ChatLog(r.roster, r.users.USER);
        return chat;
      });
  });

  run_tests();
});
