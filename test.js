/*global document:false, console:false */
define(['require', 'util'], function(require) {
  'use strict';

  var util = require('util');

  var text = x => {
    if (x instanceof ArrayBuffer || ArrayBuffer.isView(x)) {
      return util.bsHex(x, ' ');
    }
    var string = '' + x;
    if (string === ({}).toString()) {
      return JSON.stringify(x, null, 2);
    }
    return string;
  };

  var lastCheckpoint = 0;
  var stopwatch = _ => {
    var n = Date.now();
    var r = (n - lastCheckpoint) + 'ms';
    lastCheckpoint = n;
    return r;
  };

  var results_table = document.getElementById('test_results');
  var recordResult = (pass, msg, output) => {
    var record = [ pass ? '\u2714' : '\u2717', msg, stopwatch(), output ];
    console.log.apply(console, record);

    var tr = document.createElement('tr');
    tr.className = pass ? 'pass' : 'fail';
    record.forEach(e => {
      var td = document.createElement('td');
      td.textContent = text(e);
      tr.appendChild(td);
    });
    results_table.appendChild(tr);
    return tr;
  };

  var all_tests = [];
  var test = (m,f) => all_tests.push({ msg: m, func: f});

  var summary = (start, tests, failed) => {
    var passed = failed.length === 0;
    lastCheckpoint = start;
    var e = recordResult(passed, tests.length + ' tests run',
                         passed ? 'all passed'
                         : (failed.length + ' tests failed'));
    if (!passed) {
      e.addEventListener('click', _ => run(failed));
      e.title = 'Re-run all failed tests';
    }
  };

  var run = tests => {
    results_table.innerHTML = '';
    var failed = [];
    var start = Date.now();
    stopwatch();
    tests = tests || all_tests;
    return tests.reduce(
      (last, t) => last.then(t.func)
        .then(result => recordResult(true, t.msg, result),
              err => {
                failed.push(t);
                var e = recordResult(false, t.msg, err);
                e.addEventListener('click', _ => run([t]));
                e.title = 'Re-run "' + t.msg + '"';
              }),
      Promise.resolve())
      .then(_ => summary(start, tests, failed));
  };
  document.getElementById('test_run')
    .addEventListener('click', _ => run());

  var memcmp = (x, y) => util.bsEqual(x, y) && x;
  var assert = {
    fail: m => { throw new Error(m); },
    failv: (m, v) => assert.fail(m + v.map(x => ' [[' + text(x) + ']]').join('')),
    ok: x => x || assert.failv('unexpected', [x]),
    notok: x => !x && ('!' + text(x)) || assert.failv('unexpected', [x]),
    faileq: (e, a) => assert.failv('not equal', [e, a]),
    eq: (e,a) => (e === a) && a || assert.faileq(e, a),
    memcmp: (e,a) => memcmp(e, a) && a || assert.faileq(e, a)
  };

  return {
    assert: assert,
    run: run,
    test: test
  };
});
