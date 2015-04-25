define(['require', 'web-util'], function(require) {
  'use strict';

  var util = require('web-util');

  var toText = x => {
    if (x instanceof ArrayBuffer || ArrayBuffer.isView(x)) {
      return util.bsHex(x, ' ');
    }
    var string = '' + x;
    if (string === ({}).toString()) {
      return JSON.stringify(x, null, 2);
    }
    return string;
  };

  var results_table = document.getElementById('test_results');
  var recordResult = _ => {
    var pass = arguments[0];
    arguments[0] = pass ? '\u2714' : '\u2717';
    console.log.apply(console, arguments);

    var tr = document.createElement('tr');
    tr.className = pass ? 'pass' : 'fail';
    [].map.call(arguments, toText).forEach(text => {
      var td = document.createElement('td');
      td.textContent = text;
      tr.appendChild(td);
    });
    results_table.appendChild(tr);
    return tr;
  }

  var all_tests = [];
  var test = (m,f) => all_tests.push({ msg: m, func: f});

  var stopwatch = (_ => {
    var lastStopwatch = 0;
    return _ => {
      var n = Date.now();
      var r = (n - lastStopwatch) + ' ms';
      lastStopwatch = n;
      return r;
    };
  })();

  var run = tests => {
    results_table.innerHTML = '';
    stopwatch();
    var failed = [];
    var start = Date.now();
    tests = tests || all_tests;
    return tests.reduce(
      (last, t) => last.then(t.func)
        .then(result => recordResult(true, t.msg, stopwatch(), result),
              err => {
                failed.push(t);
                var e = recordResult(false, t.msg, stopwatch(), err);
                e.addEventListener('click', _ => run([t]));
                e.title = 'Re-run "' + t.msg + '"';
              }),
      Promise.resolve())
      .then(_ => {
        var passed = failed.length === 0;
        var e = recordResult(passed, 'all tests',
                             (Date.now() - start) + ' ms',
                             passed ? (tests.length + ' tests run')
                             : (failed.length + ' of ' +
                                tests.length + ' tests failed'));
        e.addEventListener('click', _ => run(failed));
        e.title = 'Re-run all failed tests';
      });
  };
  document.getElementById('test_run')
    .addEventListener('click', _ => run(), false);
  window.run_tests = run;

  var memcmp = (x, y) => (x.length === y.length) &&
      x.every((v, i) => v === y[i]) && x;
  var assert = {
    fail: m => { throw new Error(m); },
    ok: x => x || assert.fail('expected true'),
    faileq: (e, a) => assert.fail('[[' + toText(e) + ']] != [[' + toText(a) + ']]'),
    eq: (e,a) => (e === a) && a || assert.faileq(e, a),
    memcmp: (e,a) => memcmp(new Uint8Array(e), new Uint8Array(a)) && a || assert.faileq(e, a)
  };

  return {
    assert: assert,
    run: run,
    test: test
  };
});
