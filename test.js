var entity = require('./entity');
var entry = require('./rosterentry');

var zeros = new Buffer(32);
entry.RosterEntry.create(new Entity(), zeros, entry.ACTION_CREATE,
