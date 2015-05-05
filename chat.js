var reqs = ['require', 'userroster', 'agentroster', 'entity',
            'util', 'policy', 'chatlog'];
require(reqs, function(require) {
  var util = require('util');
  var Entity = require('entity').Entity;
  var PublicEntity = require('entity').PublicEntity;
  var EntityPolicy = require('policy');
  var AgentRoster = require('agentroster');
  var UserRoster = require('userroster');
  var ChatLog = require('chatlog').ChatLog;
  var base64 = util.base64url;

  var objects = {
    chat: {},
    user: {},
    group: {},
    agent: {}
  };

  const YES = '\u2714';
  const NO = '\u2717';

  var active = {};
  Object.keys(objects).forEach(k => {
    Object.defineProperty(active, k, {
      get: function() {
        var v = objects[k][this['_' + k]];
        if (!v) {
          throw new Error('create and select a ' + k);
        }
        return v;
      }
    });
    Object.defineProperty(active, k + 'id', {
      get: function() {
        return this['_' + k];
      },
      set: function(id) {
        this['_' + k] = id;
      },
    });
  });

  var elements = [
    'agentlist', 'createagent',
    'userlist', 'createuser',
    'grouplist', 'creategroup',
    'chatlist', 'createchat', 'rekeychat',
    'message', 'messagesend', 'log'
  ].reduce((all, id) => {
    all[id] = document.getElementById(id);
    return all;
  }, {});

  // Generate some basic reporting for clicks.
  var click = (n, f) => elements[n].addEventListener('click', e => {
    var p;
    try {
      p = Promise.resolve(f(e));
    } catch (e) {
      p = Promise.reject(e);
    }
    p.then(_ => console.log(YES + ' clicked ' + n),
           e => console.log(NO + ' clicked ' + n, e));
  });

  var makeElement = (name, id) => {
    if (elements[id]) {
      throw new Error('element already exists: ' + id);
    }
    var e = document.createElement(name);
    e.id = id;
    elements[id] = e;
    return e;
  };
  var make = (obj, type, makeactive) => {
    return obj.identity.then(id => {
      id = base64.encode(id);

      var div = makeElement('div', id);
      var span = makeElement('span', 'name-' + id);
      span.className = 'identifier';
      span.textContent = id;
      div.appendChild(span);
      elements[type + 'list'].appendChild(div);

      objects[type][id] = obj;

      var select = _ => {
        var oldid = active[type + 'id'];
        if (oldid) {
          elements[oldid].classList.remove('active');
        }
        div.classList.add('active');
        active[type + 'id'] = id;
        return makeactive(obj);
      };
      select();

      click('name-' + id, select);
      return div;
    });
  };

  // Clears the mark on all the old members and marks the new ones.
  var markMembers = (completeCollection, members) => {
    Object.keys(completeCollection)
      .map(k => 'member-' + k)
      .forEach(k => elements[k].textContent = NO);

    return Promise.all(members.map(agent => agent.identity))
      .then(agentids => agentids.map(aid => 'member-' + base64.encode(aid)))
      .then(agentids => agentids.forEach(aid => elements[aid].textContent = YES));
  };

  var makeMemberElement = (parent, setPolicyFunc) => {
    var id = 'member-' + parent.id;
    var memberElement = makeElement('span', id);
    memberElement.className = 'member';
    memberElement.textContent = NO;
    click(id, e => {
      var isMember = memberElement.textContent === YES;
      var policy = isMember ? EntityPolicy.NONE : EntityPolicy.USER;
      return setPolicyFunc(policy)
        .then(_ => memberElement.textContent = isMember ? NO : YES);
    });
    parent.appendChild(memberElement);
  };

  var activeAgentIsMember = _ => {
    if (active.agent) {
      if (elements['member-' + active.agentid].textContent === NO)  {
        throw new Error('selected agent must be in the user roster');
      }
    }
  };

  click('createagent', _ => {
    var agent = new Entity();
    return make(agent, 'agent', _ => {})
      .then(el => makeMemberElement(el, policy => {
        return active.user.change(active.agent, agent, policy);
      }));
  });

  click('createuser', _ => {
    return AgentRoster.create(active.agent)
      .then(roster => {
        return make(roster, 'user', _ => {
          return markMembers(objects.agent, roster.agents());
        }).then(el => makeMemberElement(el, policy => {
          return active.group.change(active.agent, active.user, roster, policy);
        }))
      });
  });

  click('creategroup', _ => {
    activeAgentIsMember();
    return UserRoster.create(active.user)
      .then(roster => make(roster, 'group', _ => {
        return markMembers(objects.user, roster.users());
      }));
  });

  var appendMessage = msg => {
    var el = document.createElement('div');
    el.className = 'message';
    el.textContent = msg;
    elements.log.appendChild(el);
  };

  click('createchat', _ => {
    activeAgentIsMember();
    var chat = new ChatLog(active.group, active.agent, active.user);
    return make(chat, 'chat', _ => {
      elements.log.innerHTML = '';
      return chat.messages.forEach(op => appendMessage(op.actor, op.message));
    });
  });

  click('rekeychat', _ => {
    return active.chat.rekey();
  });

  click('messagesend', _ => {
    return active.chat.send(elements.message.value)
      .then(_ => appendMessage(active.agent, elements.message.value));
  });
});
