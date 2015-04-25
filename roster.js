'use strict';

function handleRequest(request, response) {
  var pieces = request.url.split('/');
}

module.exports = {
  name: 'roster',
  handler: handleRequest
};
