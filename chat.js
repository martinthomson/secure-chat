var reqs = ['require', 'userroster', 'agentroster', 'entity',
            'util', 'policy', 'chatlog', 'hkdf'];
require(reqs, function(require) {
  var util = require('util');
  var Entity = require('entity').Entity;
  var PublicEntity = require('entity').PublicEntity;
  var EntityPolicy = require('policy');
  var AgentRoster = require('agentroster');
  var UserRoster = require('userroster');
  var ChatLog = require('chatlog').ChatLog;
  var base64 = util.base64url;
  var hkdf = require('hkdf');

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
    'message', 'messagesend', 'log', 'rawlog'
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

  var shortId = obj =>
      obj.identity
      .then(id => hkdf(new Uint8Array(1), id, 'shortid', 6))
      .then(id => base64.encode(id));

  var make = (obj, type, onActivate) => {
    return shortId(obj).then(id => {
      var div = makeElement('div', id);
      var span = makeElement('span', 'name-' + id);
      span.className = 'identifier';
      span.textContent = id;
      div.appendChild(span);

      var act = makeElement('span', 'active-' + id);
      act.title = 'this ' + type + ' is selected as the actor' +
        ' for changes to other objects';
      div.appendChild(act);

      var select = _ => {
        var oldid = active[type + 'id'];
        if (oldid) {
          elements[oldid].classList.remove('active');
          elements['active-' + oldid].textContent = '';
        }
        div.classList.add('active');
        act.textContent = '\u270a';

        active[type + 'id'] = id;
        return onActivate(obj);
      };
      select();

      click('name-' + id, select);
      objects[type][id] = obj;
      elements[type + 'list'].appendChild(div);
      return div;
    });
  };

  // Clears the mark on all the old members and marks the new ones.
  var markMembers = (completeCollection, members) => {
    Object.keys(completeCollection)
      .map(k => 'member-' + k)
      .forEach(k => elements[k].textContent = NO);

    return Promise.all(members.map(agent => shortId(agent)))
      .then(agentids => agentids
            .forEach(aid => elements['member-' + aid].textContent = YES));
  };

  var makeMemberElement = (parent, setPolicyFunc) => {
    var id = 'member-' + parent.id;
    var memberElement = makeElement('span', id);
    memberElement.className = 'member';
    memberElement.title = 'indicates if this is part of the active roster';
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

  var makeInChatElement = parent => {
    var id = 'chat-' + parent.id;
    var el = makeElement('span', id);
    el.className = 'inchat';
    el.title = 'this is being used for the currently selected chat';
    parent.appendChild(el);
  };

  var markInChat = (completeCollection, active) => {
    Object.keys(completeCollection)
      .map(k => 'chat-' + k)
      .forEach(k => elements[k].textContent = '');

    return shortId(active)
      .then(id => elements['chat-' + id].textContent = '\ud83d\ude2e');
  };

  var makeLogElement = (obj, parent) =>  {
    var id = 'log-' + parent.id;
    var el = makeElement('span', id);
    el.className = 'rawlog';
    el.title = 'show the raw contents of the log';
    el.textContent = '\ud83d\udcdd';
    click(id, _ => {
      elements.rawlog.value = base64.encode(obj.encode());
    });
    parent.appendChild(el);
  };

  click('createagent', _ => {
    var agent = new Entity();
    return make(agent, 'agent', _ => {})
      .then(el => {
        makeInChatElement(el);
        return makeMemberElement(el, policy => {
          return active.user.change(active.agent, agent, policy);
        });
      });
  });

  click('createuser', _ => {
    return AgentRoster.create(active.agent)
      .then(roster => {
        return make(roster, 'user', _ => {
          return markMembers(objects.agent, roster.agents());
        }).then(el => {
          makeInChatElement(el);
          makeLogElement(roster, el);
          return makeMemberElement(el, policy => {
            return active.group.change(active.agent, active.user,
                                       roster, policy);
          });
        })
      });
  });

  click('creategroup', _ => {
    activeAgentIsMember();
    return UserRoster.create(active.user)
      .then(roster => {
        return make(roster, 'group', _ => {
          return markMembers(objects.user, roster.users());
        }).then(el => {
          makeInChatElement(el);
          makeLogElement(roster, el);
        })
      });
  });

  var appendMessage = (sender, msg) => {
    return shortId(sender).then(id => {
      var el = document.createElement('div');

      var senderElement = document.createElement('span');
      senderElement.className = 'sender';
      senderElement.textContent = id;
      el.appendChild(senderElement);

      var messageElement = document.createElement('span');
      messageElement.className = 'message';
      messageElement.textContent = msg;
      el.appendChild(messageElement);

      elements.log.appendChild(el);
    });
  };

  click('createchat', _ => {
    activeAgentIsMember();
    var group = active.group;
    var agent = active.agent;
    var user = active.user;
    var chat = new ChatLog(group, agent, user);
    return make(chat, 'chat', _ => {
      elements.log.innerHTML = '';
      return Promise.all(
        [
          markInChat(objects.agent, agent),
          markInChat(objects.user, user),
          markInChat(objects.group, group)
        ].concat(chat.messages.map(op => appendMessage(op.user, op.text)))
      );
    }).then(el => makeLogElement(chat, el));
  });

  click('rekeychat', _ => {
    return active.chat.rekey();
  });

  click('messagesend', _ => {
    return active.chat.send(elements.message.value)
      .then(_ => appendMessage(active.chat.user, elements.message.value));
  });
});
