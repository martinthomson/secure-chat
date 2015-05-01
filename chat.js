var reqs = ['require', 'userroster', 'agentroster', 'entity', 'util', 'policy'];
require(reqs, function(require) {
  var util = require('util');
  var Entity = require('entity').Entity;
  var PublicEntity = require('entity').PublicEntity;
  var EntityPolicy = require('policy');
  var AgentRoster = require('agentroster');
  var UserRoster = require('userroster');
  var base64 = util.base64url;

  var elements = [
    'agentrosterid', 'agentroster', 'agentrosterupdate',
    'agentid', 'agentadd', 'agentremove',
    'userrosterid', 'userroster', 'userrosterupdate',
    'otheruserid', 'otheruseradd', 'otheruserremove',
    'userid', 'rekey', 'message', 'messagesend', 'log'
  ].reduce((all, id) => {
    all[id] = document.getElementById(id);
    return all;
  }, {});

  var user = new Entity();
  var agentroster = AgentRoster.create(user);
  var userroster = agentroster.then(roster => UserRoster.create(roster));

  user.identity
    .then(id => elements.userid.value = base64.encode(id));

  var updateRosters = _ => {
    console.log('update');
    return Promise.all([
      agentroster.then(
        roster => roster.identity
          .then(id => elements.agentrosterid.value = base64.encode(id))
          .then(_ => console.log('agent roster update', roster))
          .then(_ => elements.agentroster.value = base64.encode(roster.encode()))
      ),
      userroster.then(
        roster => roster.identity
          .then(id => elements.userrosterid.value = base64.encode(id))
          .then(_ => console.log('user roster update', roster))
          .then(_ => elements.userroster.value = base64.encode(roster.encode()))
      )
    ]).catch(e => console.log('error', e));
  };

  updateRosters();

  var lastop = Promise.resolve();
  var op =
      (element, f) => element.addEventListener(
        'click', _ => lastop = lastop.then(f).then(updateRosters));

  op(elements.agentrosterupdate, _ => {
    var log = base64.decode(elements.agentroster.value);
    var roster = new AgentRoster();
    agentroster = roster.decode(log).then(_ => roster);
    updateRosters();
  });

  op(elements.userrosterupdate, _ => {
    var log = base64.decode(elements.userroster.value);
    var roster = new UserRoster();
    userroster = roster.decode(log).then(_ => roster);
    updateRosters();
  });

  var setAgentPolicy = policy => {
    var id = base64.decode(elements.agentid.value);
    var agent = new PublicEntity(id);
    agentroster.then(roster => roster.change(user, agent, policy))
      .then(updateRosters);
  };
  op(elements.agentadd, _ => setAgentPolicy(EntityPolicy.USER));
  op(elements.agentremove, _ => setAgentPolicy(EntityPolicy.NONE));

  var setUserPolicy = policy => {
    var id = base64.decode(elements.otheruserid.value);
    var otheruser = new PublicEntity(id);
    userroster.then(roster => roster.change(user, otheruser, policy))
      .then(updateRosters);
  };
  op(elements.otheruseradd, _ => setUserPolicy(EntityPolicy.USER));
  op(elements.otheruserremove, _ => setUserPolicy(EntityPolicy.NONE));

  op(elements.rekey, _ => {
    var key = crypto.getRandomValues(32);
    userroster.then(roster => {
      return Promise.all(
        roster.members()
          .map(
            member => Promise.all([
              member.identity,
              user.encryptKey(member.share, key)
            ]).then(util.bsConcat)
          )
      ).then(util.bsConcat);
    });
  });
});
