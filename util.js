define(['require'], function(require) {
  'use strict';

  /** bs stands for BufferSource */

  /** A utility function for concatenating ArrayBuffers or views thereof. */
  function bsConcat(arrays) {
    var size = arrays.reduce((total, a) => total + a.byteLength, 0);
    var index = 0;
    return arrays.reduce((result, a) => {
      result.set(new Uint8Array(a), index);
      index += a.byteLength;
      return result;
    }, new Uint8Array(size));
  }

  /** Constant time for equal length buffers. */
  function bsEqual(a, b) {
    a = new Uint8Array(a);
    b = new Uint8Array(b);
    if (a.length !== b.length) {
      return false;
    }
    return !a.reduce((eq, v, i) => eq + (v ^ b[i]), 0);
  }

  /** Produce a hex string with the given separator. */
  function bsHex(a, sep) {
    return new Uint8Array(a)
      .join(' ').split(' ')
      .map(x => parseInt(x, 10))
      .map(x => ((x < 16) ? '0' : '') + x.toString(16))
      .join(sep || '');
  }

  function bsDivide(a, size) {
    a = ArrayBuffer.isView(a) ? a.buffer : a;
    var offset = a.byteOffset || 0;
    var result = [];
    for (var i = 0; i + size <= a.byteLength; i += size) {
      result.push(new Uint8Array(a, offset + i, size));
    }
    var remainder = a.byteLength % size;
    if (remainder) {
      result.push(new Uint8Array(a, offset + a.byteLength - remainder));
    }
    return result;
  }

  /* I can't believe that this is needed here, in this day and age ...
   * Note: these are not efficient, merely expedient.
   */
  var base64url = {
    _strmap: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
    encode: function(data) {
      data = new Uint8Array(data);
      var len = Math.ceil(data.length * 4 / 3);
      return bsDivide(data, 3).map(chunk => [
        chunk[0] >>> 2,
        ((chunk[0] & 0x3) << 4) | (chunk[1] >>> 4),
        ((chunk[1] & 0xf) << 2) | (chunk[2] >>> 6),
        chunk[2] & 0x3f
      ].map(v => base64url._strmap[v]).join('')).join('').slice(0, len);
    },
    _lookup: function(s, i) {
      return base64url._strmap.indexOf(s.charAt(i));
    },
    decode: function(str) {
      var v = new Uint8Array(Math.floor(str.length * 3 / 4));
      var vi = 0;
      for (var si = 0; si < str.length;) {
        var w = base64url._lookup(str, si++);
        var x = base64url._lookup(str, si++);
        var y = base64url._lookup(str, si++);
        var z = base64url._lookup(str, si++);
        v[vi++] = w << 2 | x >>> 4;
        v[vi++] = x << 4 | y >>> 2;
        v[vi++] = y << 6 | z;
      }
      return v;
    }
  };

  function Parser(buf) {
    this.position = buf.byteOffset || 0;
    this._buf = ArrayBuffer.isView(buf) ? buf.buffer : buf;
  }
  Parser.prototype = {
    next: function(len) {
      var chunk = new Uint8Array(this._buf, this.position, len);
      this.position += len;
      console.log(chunk, len);
      return chunk;
    },
    range: function(start, end) {
      return new Uint8Array(this._buf, start, end - start);
    }
  };

  /** Like Promise.all(), except that it takes and returns an object. */
  function promiseDict(o) {
    var result = {};
    return Promise.all(
      Object.keys(o).map(
        k => Promise.resolve(o[k]).then(r => result[k] = r)
      )
    ).then(_ => result);
  }

  /** Merges the list of dictionaries.  With `host`, it merges into the provided
   * object; without host, it creates a new one. */
  function mergeDict(objs, host) {
    return objs.reduce((c, o) => {
      Object.keys(o).forEach(k => c[k] = o[k]);
      return c;
    }, host || {});
  }

  return {
    base64url: base64url,
    bsConcat: bsConcat,
    bsDivide: bsDivide,
    bsEqual: bsEqual,
    bsHex: bsHex,
    mergeDict: mergeDict,
    promiseDict: promiseDict,
    Parser: Parser
  };
});
