'use strict';

var handlers = [ 'roster' ]
    .reduce(function(all, n) {
      var h = require('./' + n);
      all[h.name] = h.handler;
      return all;
    }, {});

function handleRequest(request, response) {
  var name = request.url.substring(1).split('/', 1)[0];
  if (typeof handlers[name] === 'function') {
    return handlers[name](request, response);
  }

  response.setHeader('Content-Type', 'text/plain;charset=utf-8');
  if (request.url === '/') {
    response.writeHead(200);
  } else {
    response.writeHead(404);
  }
  response.end('Valid paths: ' +
               Object.keys(handlers)
                     .map(function(p) { return '/' + p; })
                     .join(', ') + '\n');
}

require('fs').readFile('./server.pfx', function(err, data) {
  var server = require('https')
    .createServer({ pfx: data }, handleRequest);
  server.listen(38120);
});
