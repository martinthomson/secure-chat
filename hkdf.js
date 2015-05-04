define(['util'], function(util) {
  var HMAC_SHA256 = { name: 'HMAC', hash: 'SHA-256' };
  function hmac(key) {
    this.keyPromise = crypto.subtle.importKey('raw', key, HMAC_SHA256,
                                              false, ['sign']);
  }
  hmac.prototype.hash = function(input) {
    return this.keyPromise.then(k => crypto.subtle.sign('HMAC', k, input));
  }

  function hkdf(salt, ikm, info, len) {
    return new hmac(salt).hash(ikm)
      .then(prk => new hmac(prk))
      .then(prkh => {
        var output = [];
        var counter = new Uint8Array(1);

        function hkdf_iter(t) {
          if (++counter[0] === 0) {
            throw new Error('Too many hmac invocations for hkdf');
          }
          return prkh.hash(util.bsConcat([t, info, counter]))
            .then(tnext => {
              tnext = new Uint8Array(tnext);
              output.push(tnext);
              if (output.reduce((sum, a) => sum + a.length, 0) >= len) {
                return output;
              }
              return hkdf_iter(tnext);
            });
        }

        return hkdf_iter(new Uint8Array(0));
      })
      .then(chunks => util.bsConcat(chunks).slice(0, len));
  }
  return hkdf;
});
