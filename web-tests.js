var deps = ['require', 'web-entity', 'web-policy',
            'web-roster', 'web-util', 'web-test'];
require(deps, function(require) {
  'use strict';

  var run = require('web-test').run;
  var test = require('web-test').test;
  var assert = require('web-test').assert;

  var EntityPolicy = require('web-policy');

  var policyOrder = [ EntityPolicy.ADMIN, EntityPolicy.USER,
                EntityPolicy.OBSERVER, EntityPolicy.NONE ];
  test('policy pecking order', _ => {
    return policyOrder.every((superior, i) => {
      return assert.ok(superior.equals(superior)) &&
        policyOrder.slice(i).every(
          inferior => assert.ok(superior.subsumes(inferior))
        )
    });
  });
  test('policy encode/decode', _ => {
    return policyOrder.every(input => {
      var output = EntityPolicy.decode(input.encode());
      console.log(input, output);
      return assert.ok(input.equals(output));
    });
  });

  var Entity = require('web-entity').Entity;

  test('entity identity', _ => new Entity().identity);
  test('entity share', _ => new Entity().share);
  test('sign and verify', _ => {
    var e = new Entity;
    var msg = new Uint8Array(1);
    return e.sign(msg)
      .then(sig => e.verify(sig, msg))
      .then(assert.ok);
  });

  var AgentRoster = require('web-roster').AgentRoster;

  test('create roster', _ => AgentRoster.create(new Entity()));
  test('create roster and check it', _ => {
    var user = new Entity();
    return AgentRoster.create(user)
      .then(roster => roster.find(user))
      .then(found => {
        return Promise.all([found.subject.identity,
                            user.identity])
          .then(id => assert.memcmp(id[0], id[1]));
      });
  });
  test('create roster and leave', _ => {
    var user = new Entity();
    return AgentRoster.create(user)
       .then(roster => roster.canChange(user, user, EntityPolicy.NONE))
       .then(assert.ok);
  });
  run_tests();
});
