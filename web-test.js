require(['require', 'web-entity', 'web-policy', 'web-roster', 'web-util'], function(require) {
  'use strict';

  var util = require('web-util');
  var roster = require('web-roster');
  var AgentRoster = require('web-roster').AgentRoster;
  var Entity = require('web-entity').Entity;
  var EntityPolicy = require('web-policy');

  var table = document.getElementById('results');
  var toText = x => {
    if (x instanceof ArrayBuffer || ArrayBuffer.isView(x)) {
      return util.bsHex(x, ' ');
    }
    var string = x.toString();
    if (string === ({}).toString()) {
      return JSON.stringify(x, null, 2);
    }
    return string;
  };
  var show = args => {
    console.log.apply(console, arguments);
    var tr = document.createElement('tr');
    [].map.call(arguments, toText).forEach(text => {
      var td = document.createElement('td');
      td.textContent = text;
      tr.appendChild(td);
    });
    table.appendChild(tr);
  }
  var lastTest = Promise.resolve();
  var test = (m,p) => {
    lastTest = lastTest.then(_ => (typeof p === 'function') ? p() : p)
      .then(r => show('\u2714', m, r), e => show('\u2717', m, e));
    return lastTest;
  };
  var fail = m => { throw m; }
  var assertTrue = x => x || fail('expected true');
  var memcmp = (x, y) => x.length === y.length && x.every((v, i) => v === y[i]) && x;
  var assertMemcmp = (x,y) => memcmp(x, y) || fail('expected equal');
  var assertEqual = (x,y) => (x === y) && x || fail('expected equal');

  test('object lengths', roster.RosterEntry.lengths);
  test('entity identity', new Entity().identity);
  test('entity share', new Entity().share);
  test('sign and verify', _ => {
    var e = new Entity;
    var msg = new Uint8Array(1);
    return e.sign(msg)
      .then(sig => e.verify(sig, msg))
      .then(assertTrue);
  });
  test('create roster', _ => AgentRoster.create(new Entity(), EntityPolicy.USER));
});
