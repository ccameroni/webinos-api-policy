/*******************************************************************************
 *  Code contributed to the webinos project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright 2013 Torsec -Computer and network security group-
 * Politecnico di Torino
 *
 ******************************************************************************/

var friendsURI = 'http://webinos.org/subject/id/known';

var getPolicy_ServiceForPeople = function() {
    var requestorId = null;
    var userId = arguments[0];
    var serviceId = arguments[1];
    if (arguments.length == 3) {
        var successCB = arguments[2];
    } else if ( arguments.length == 4 ) {
        var requestorId = arguments[2];
        var successCB = arguments[3];
    }
    webinos.discovery.findServices(new ServiceType('http://webinos.org/core/policymanagement'), {
        onFound: function(service) {
            policyeditor = service;
            policyeditor.bindService({
                onBind: function(service) {
                    policyeditor.getPolicySet(0, function(ps) {
                        var request = {};
                        request.subjectInfo = {};
                        request.subjectInfo.userId = userId;
                        request.resourceInfo = {};
                        if (isWebinosAPI(serviceId)) {
                            request.resourceInfo.apiFeature = serviceId;
                        }
                        else {
                            request.resourceInfo.serviceId = serviceId;
                        }
                        if(requestorId != null) {
                            request.deviceInfo = {};
                            request.deviceInfo.requestorId = requestorId;
                        }

                        var policy = ps.toJSONObject()
                        policyeditor.testPolicy(ps, request, function(res) {
                            if (res.effect == 0) {
                                successCB('enable');
                            }
                            else if (res.effect == 1) {
                                successCB('disable');
                            }
                            else {
                                successCB(null);
                            }
                        });
                    }, null);
                }
            });
        }
    });
};


var getPolicy_ServicesForPeople = function() {
    var requestorId = null;
    var userId = arguments[0];

    if (arguments.length == 2) {
        var successCB = arguments[1];
    } else if (arguments.length == 3) {
        var requestorId = arguments[1];
        var successCB = arguments[2];
    }


    var result = [];
    var done = function(callback) {
        var counter = 0;
        return function (incr) {
            if (0 == (counter += incr))
                callback();
        };
    };

    var sync = done(function() { successCB(result); });

    var test = function (ps, request, i) {
        sync(+1);
        policyeditor.testPolicy(ps, request, function(res) {
            if (res.effect == 0) {
                result[i].access = 'enable';
            }
            else if (res.effect == 1) {
                result[i].access = 'disable';
            }
            else {
                result[i].access = null;
            }
            sync(-1);
        });

    };

    webinos.discovery.findServices(new ServiceType('http://webinos.org/core/policymanagement'), {
        onFound: function(service) {
            policyeditor = service;
            policyeditor.bindService({
                onBind: function(service) {
                    policyeditor.getPolicySet(0, function(ps) {
                        var policy = ps.toJSONObject()
                        var policyString = JSON.stringify(policy);

                        var services = getMatch(policyString, 'service-id');
                        for (var i = 0; i < services.length; i++) {
                            var request = {};
                            request.subjectInfo = {};
                            request.subjectInfo.userId = userId;
                            request.resourceInfo = {};
                            request.resourceInfo.serviceId = services[i];

                            if (requestorId != null) {
                                request.deviceInfo = {};
                                request.deviceInfo.requestorId = requestorId;
                            }

                            var service = {};
                            service.serviceId = services[i];
                            result.push(service);
                            test(ps, request, i);
                        }

                        var apis = getMatch(policyString, 'api-feature');
                        for (var i = 0; i < apis.length; i++) {
                            var request = {};
                            request.subjectInfo = {};
                            request.subjectInfo.userId = userId;
                            request.resourceInfo = {};
                            request.resourceInfo.apiFeature = apis[i];

                            if (requestorId != null) {
                                request.deviceInfo = {};
                                request.deviceInfo.requestorId = requestorId;
                            }

                            var service = {};
                            service.serviceId = apis[i];
                            result.push(service);
                            test(ps, request, i + services.length);
                        }
                    }, null);
                }
            });
        }
    });
};

var getPolicy_PeopleForServices = function() {
    var requestorId = null;
    var serviceId = arguments[0];
    if (arguments.length == 2) {
        var successCB = arguments[1];
    } else if (arguments.length == 3) {
        var requestorId = arguments[1];
        var successCB = arguments[2];
    }

    var result = [];
    var done = function(callback) {
        var counter = 0;
        return function (incr) {
            if (0 == (counter += incr))
                callback();
        };
    };
    var sync = done(function() { successCB(result); });
    var test = function (ps, request, user) {
        sync(+1);
        policyeditor.testPolicy(ps, request, function(res) {
            if (res.effect == 0) {
                result.push(user);
            }
            sync(-1);
        });
    };

    webinos.discovery.findServices(new ServiceType('http://webinos.org/core/policymanagement'), {
        onFound: function(service) {
            policyeditor = service;
            policyeditor.bindService({
                onBind: function(service) {
                    policyeditor.getPolicySet(0, function(ps) {
                        var policy = ps.toJSONObject()
                        var policyString = JSON.stringify(policy);
                        var users = getMatch(policyString, 'user-id');

                        for (var i = -1; i < users.length; i++) {
                            var request = {};
                            request.resourceInfo = {};
                            if (isWebinosAPI(serviceId)) {
                                request.resourceInfo.apiFeature = serviceId;
                            }
                            else {
                                request.resourceInfo.serviceId = serviceId;
                            }

                            if(requestorId != null) {
                                request.deviceInfo = {};
                                request.deviceInfo.requestorId = requestorId;
                            }

                            if (i > -1) {
                                request.subjectInfo = {};
                                request.subjectInfo.userId = users[i];
                                test(ps, request, users[i]);
                            }
                            else {
                                test(ps, request, 'anyUser');
                            }

                        }
                    }, null);
                }
            });
        }
    });
};

function getMatch(policy, string) {
    var obj = {}, ret = [];

    var exp = new RegExp('"' + string + '"\s*,\s*"match"\s*:\s*"([^"]*)', 'g');
    extractItems(policy, exp, obj);
    var exp = new RegExp('match"\s*:\s*"([^"]*)"\s*,\s*"attr"\s*:\s*"' + string + '"', 'g');
    extractItems(policy, exp, obj);

    if (string == 'user-id') {
        // add zone owner
        var zoneOwner = webinos.session.getPZHId()
        if (zoneOwner) {
            obj[zoneOwner] = 0;
        }
        else { // PZP not enrolled
            obj[webinos.session.getPZPId()] = 0;
        }
        // add friends
        var friends = webinos.session.getConnectedPzh();
        for (var i in friends) {
            obj[friends[i]] = 0;
        }
    }

    for (var i in obj) {
        ret.push(i);
    }
    return ret;
}

var extractItems = function(policy, exp, obj) {
    var genericURIs = [
        'http://webinos.org/subject/id/PZ-Owner',
        'http://webinos.org/subject/id/known'
    ];

    while (val = exp.exec(policy)) {
        // split required to manage bags
        var items = val[1].split(',');
        for (var i in items) {
            item = items[i].trim();
            // skip generic URIs
            if (genericURIs.indexOf(item) == -1) {
                obj[item] = 0;
            }
        }
    }
}

// input formats
// with device: setPolicy_ServiceForPeople(userId, serviceId, requestorId, access, successCB, errorCB);
// without device: setPolicy_ServiceForPeople(userId, serviceId, access, successCB, errorCB);
var setPolicy_ServiceForPeople = function() {
    var userId = arguments[0];
    var serviceId = arguments[1];
    var requestorId = null;
    if (arguments.length == 5) {
        var access = arguments[2];
        var successCB = arguments[3];
        var errorCB = arguments[4];
    } else if (arguments.length == 6) {
        var requestorId = arguments[2]
        var access = arguments[3];
        var successCB = arguments[4];
        var errorCB = arguments[5];
    }

    webinos.discovery.findServices(new ServiceType('http://webinos.org/core/policymanagement'), {
        onFound: function(service) {
            policyeditor = service;
            policyeditor.bindService({
                onBind: function(service) {
                    policyeditor.getPolicySet(0, function(ps) {
                        var request = {};
                        request.subjectInfo = {};
                        request.subjectInfo.userId = userId;
                        request.resourceInfo = {};
                        if (isWebinosAPI(serviceId)) {
                            request.resourceInfo.apiFeature = serviceId;
                        }
                        else {
                            request.resourceInfo.serviceId = serviceId;
                        }
                        if (requestorId != null) {
                            request.deviceInfo = {};
                            request.deviceInfo.requestorId = requestorId;
                        }
                        policyeditor.testPolicy(ps, request, function(res) {
                            if ((access == 'enable' && res.effect != 0) ||
                                (access == 'disable' && res.effect != 1)) {

                                var newPs = editPolicy(policyeditor, ps, access, request, res);
                                if (!newPs.error) {
                                    policyeditor.testNewPolicy(newPs, request, function (result) {
                                        if ((access == 'enable' && result.effect == 0) ||
                                            (access == 'disable' && result.effect == 1)) {
                                            policyeditor.save(newPs, function() {
                                                successCB('save succesful');
                                            }, function() {
                                                errorCB('save failed');
                                            });
                                        } else {
                                            errorCB('editing failed');
                                        }
                                    }, null);
                                } else {
                                    errorCB(newPs.error);
                                }
                            }
                            else {
                                successCB();
                            }
                        });
                    }, null);
                }
            });
        }
    });
};

var editPolicy = function (pe, ps, access, request, res) {
    var userId = request.subjectInfo.userId;
    var serviceId = null;
    if (request.resourceInfo.serviceId) {
        serviceId = request.resourceInfo.serviceId;
    }
    else if (request.resourceInfo.apiFeature) {
        serviceId = request.resourceInfo.apiFeature;
    }
    var requestorId = null;
    var date = new Date().getTime();
    if (request.deviceInfo) {
        requestorId = request.deviceInfo.requestorId;
    }

    if (requestorId != null) {
        var policySet = ps.getPolicySet([userId]);
        if (policySet.matched.length > 0) {
            policySet = policySet.matched[0].toJSONObject();
            var policy = null;
            var userIds = policySet.target[0].subject[0]['subject-match'][0].$.match.split(',');
            // check if target contains the friends generic URI or a bag
            if (policySet.target[0].subject[0]['subject-match'][0].$.match === friendsURI || userIds.length > 1) {
                if (userIds.length > 1) {
                    var index = userIds.indexOf(userId);
                    userIds.splice(index, 1);
                    policySet.target[0].subject[0]['subject-match'][0].$.match = userIds.toString();
                }
                // make a copy of the policySet (clone object)
                policySet = JSON.parse(JSON.stringify(policySet));
                // modify policySet ids
                policySet.$.id = 'ps_' + userId + '_' + date;
                policySet.$.description = userId + '-policySet';
                // modify target to replace the generic URI
                policySet.target[0].subject[0]['subject-match'][0].$.match = userId;
                for (var i = 0; i < policySet.policy.length; i++) {
                    // modify policy's and rules' ids
                    var id = 'Default';
                    if (policySet.policy[i].target) {
                        var id = policySet.policy[i].target[0].subject[0]['subject-match'][0].$.match;
                    }
                    policySet.policy[i].$.id = 'p_' + userId + id + '_' + date;
                    policySet.policy[i].$.description = userId + id + '-policy';
                    for (var j = 0; j < policySet.policy[i].rule.length; j++) {
                        policySet.policy[i].rule[j].$.id = 'r_' + userId + id + '_' + ++date;
                    }
                }
            }
            // policy set without friends URI
            else {
                // remove old policy set
                ps.removePolicySet(policySet.$.id);
            }
            var policySetObject = new pe.policyset(policySet);
            var result = policySetObject.getPolicy([requestorId]);
            if (result.matched.length > 0) {
                policy = result.matched[0].toJSONObject();
            }
            else if (result.generic.length > 0) {
                // start from default policy when adding a new device
                policy = result.generic[0].toJSONObject();
            }
        }
        // Start from default policy set when adding a new user
        else if (policySet.generic.length > 0) {
            policySet = policySet.generic[0].toJSONObject();
            // make a copy of the policySet (clone object)
            policySet = JSON.parse(JSON.stringify(policySet));
            // modify policySet ids
            policySet.$.id = 'ps_' + userId + '_' + date;
            policySet.$.description = userId + '-policySet';
            for (var i = 0; i < policySet.policy.length; i++) {
                // modify policy's and rules' ids
                var id = 'Default';
                if (policySet.policy[i].target) {
                    var id = policySet.policy[i].target[0].subject[0]['subject-match'][0].$.match;
                }
                policySet.policy[i].$.id = 'p_' + userId + id + '_' + date;
                policySet.policy[i].$.description = userId + id + '-policy';
                for (var j = 0; j < policySet.policy[i].rule.length; j++) {
                    policySet.policy[i].rule[j].$.id = 'r_' + userId + id + '_' + ++date;
                }
            }
            policySet.target = [];
            policySet.target.push({'subject': [{'subject-match': [{'$' : {'attr' : 'user-id', 'match' : userId}}]}]});
            var policySetObject = new pe.policyset(policySet);
            var result = policySetObject.getPolicy([requestorId]);
            if (result.matched.length > 0) {
                policy = result.matched[0].toJSONObject();
            }
            else if (result.generic.length > 0) {
                // start from default policy when adding a new device
                policy = result.generic[0].toJSONObject();
            }
        }
        // add new policySet
        else {
            policySet = ps.createPolicySet('ps_' + userId + '_' + date, 'first-matching-target', userId + '-policy');
            policySet = policySet.toJSONObject();
            // add default rule
            policySet.policy = [];
            policySet.policy.push({'rule': [{'$' : {'effect' : 'deny', 'id' : 'r_' + userId + '_default'}}]});
        }
        if (policy != null) {
            // this is not the default policy
            if (policy.target) {
                var requestorIds = policy.target[0].subject[0]['subject-match'][0].$.match.split(',');
                // check if target contains a bag
                if (requestorIds.length > 1) {
                    var index = requestorIds.indexOf(requestorId);
                    requestorIds.splice(index, 1);
                    policy.target[0].subject[0]['subject-match'][0].$.match = requestorIds.toString();
                    // make a copy of the policy (clone object)
                    policy = JSON.parse(JSON.stringify(policy));
                    // modify policy's and rules' ids
                    policy.$.id = 'p_' + userId + requestorId + '_' + date;
                    policy.$.description = userId + requestorId + '-policy';
                    for (var i = 0; i < policy.rule.length; i++) {
                        policy.rule[i].$.id = 'r_' + userId + requestorId + '_' + ++date;
                    }
                    // modify target to replace the generic URI
                    policy.target[0].subject[0]['subject-match'][0].$.match = requestorId;
                    policySet.policy.splice(0, 0, policy);
                }
            }
            // this is the default policy
            else {
                // make a copy of the policy (clone object)
                policy = JSON.parse(JSON.stringify(policy));
                // modify policy's and rules' ids
                policy.$.id = 'p_' + userId + requestorId + '_' + date;
                policy.$.description = userId + requestorId + '-policy';
                for (var i = 0; i < policy.rule.length; i++) {
                    policy.rule[i].$.id = 'r_' + userId + requestorId + '_' + ++date;
                }
                // add target
                policy.target = [];
                policy.target.push({'subject': [{'subject-match': [{'$' : {'attr' : 'requestor-id', 'match' : requestorId}}]}]});
                policySet.policy.splice(0, 0, policy);
            }
            policy = removeOldResourceMatch(policy, serviceId, access);
        }
        // add new policy
        else {
            policy = createNewPolicy(ps, 'requestor-id', requestorId, userId + requestorId, date);
            policySet.policy.splice(0, 0, policy);
        }
        policy = addResource(policy, userId + requestorId, serviceId, access, ++date);

        var newPolicySet = new pe.policyset(policySet);
        ps.addPolicySet(newPolicySet, 0);

    }
    // policy without devices
    else {
        var policy = ps.getPolicy([userId]);
        var position = 0;
        if (policy.matched.length > 0) {
            policy = policy.matched[0].toJSONObject();
            var path = JSON.parse(res.user.path);
            for (var i = 0; i < path.policy.length; i++) {
                if (path.policy[i].id === policy.$.id) {
                    position = path.policy[i].position;
                    break;
                }
            }
            var userIds = policy.target[0].subject[0]['subject-match'][0].$.match.split(',');
            // check if target contains the friends generic URI or a bag
            if (policy.target[0].subject[0]['subject-match'][0].$.match === friendsURI || userIds.length > 1) {
                if (userIds.length > 1) {
                    var index = userIds.indexOf(userId);
                    userIds.splice(index, 1);
                    policy.target[0].subject[0]['subject-match'][0].$.match = userIds.toString();
                }
                // make a copy of the policy (clone object)
                policy = JSON.parse(JSON.stringify(policy));
                // modify policy's and rules' ids
                policy.$.id = 'p_' + userId + '_' + date;
                policy.$.description = userId + '-policy';
                for (var i = 0; i < policy.rule.length; i++) {
                    policy.rule[i].$.id = 'r_' + userId + '_' + ++date;
                }
                // modify target to replace the generic URI
                policy.target[0].subject[0]['subject-match'][0].$.match = userId;
            }
            else {
                // remove the old policy
                ps.removePolicy(policy.$.id);
            }

            policy = removeOldResourceMatch(policy, serviceId, access);
        } else {
            if (policy.generic.length > 0) {
                policy = policy.generic[0].toJSONObject();
                var path = JSON.parse(res.user.path);
                for (var i = 0; i < path.policy.length; i++) {
                    if (path.policy[i].id === policy.$.id) {
                        position = path.policy[i].position;
                        break;
                    }
                }
                // make a copy of the policy (clone object)
                policy = JSON.parse(JSON.stringify(policy));
                // modify policy's and rules' ids
                policy.$.id = 'p_' + userId + '_' + date;
                policy.$.description = userId + '-policy';
                for (var i = 0; i < policy.rule.length; i++) {
                    policy.rule[i].$.id = 'r_' + userId + '_' + ++date;
                }
                // add target
                policy.target = [];
                policy.target.push({'subject': [{'subject-match': [{'$' : {'attr' : 'user-id', 'match' : userId}}]}]});
                policy = removeOldResourceMatch(policy, serviceId, access);
            }
            else {
                // new user, add policy
                policy = createNewPolicy(ps, 'user-id', userId, userId, date);
            }
        }

        policy = addResource(policy, userId, serviceId, access, ++date);

        var newPolicy = new pe.policy(policy);
        ps.addPolicy(newPolicy, position);
    }

    return ps;
};

var removeOldResourceMatch = function (policy, serviceId, access) {
    var removedResourceMatch = false
    for (var i = 0; i < policy.rule.length; i++) {
        if ((policy.rule[i].$.effect == 'permit' && access == 'disable') ||
            (policy.rule[i].$.effect == 'deny' && access == 'enable')) {
            if (policy.rule[i].condition && (policy.rule[i].condition[0].$.combine == 'or' ||
                (policy.rule[i].condition[0].$.combine == 'and' && policy.rule[i].condition[0]['resource-match'].length < 2))) {

                for (var j = 0; j < policy.rule[i].condition[0]['resource-match'].length; j++) {
                    if (policy.rule[i].condition[0]['resource-match'][j].$.match == serviceId) {
                        policy.rule[i].condition[0]['resource-match'].splice(j,1);
                        removedResourceMatch = true;
                        break;
                    }
                }
                if (removedResourceMatch == true && policy.rule[i].condition[0]['resource-match'].length == 0) {
                    policy.rule.splice(i,1);
                    break;
                }
            }
        }
    }
    return policy;
}

var createNewPolicy = function (ps, attr, match, id, date) {
    var policy = ps.createPolicy('p_' + id + '_' + date, 'first-applicable', id + '-policy');
    var subject = {};
    subject['subject-match'] = [];
    subject['subject-match'].push({'$' : {'attr' : attr, 'match' : match}});
    policy.addSubject('s_' + id, subject);
    policy = policy.toJSONObject();
    // add default rule
    policy.rule = [];
    policy.rule.push({'$' : {'effect' : 'deny', 'id' : 'r_' + id + '_default'}});
    return policy;
}

var addResource = function (policy, Id, serviceId, access, date) {
    var addedResourceMatch = false;

    // add new resource match
    for (var i = 0; i < policy.rule.length; i++) {
        if (((policy.rule[i].$.effect == 'permit' && access == 'enable') ||
            (policy.rule[i].$.effect == 'deny' && access == 'disable')) &&
            policy.rule[i].condition && (policy.rule[i].condition[0].$.combine == 'or' ||
            (policy.rule[i].condition[0].$.combine == 'and' && policy.rule[i].condition[0]['resource-match'].length == 1))) {

            var resourceMatch = {};
            resourceMatch.$ = {};
            if (isWebinosAPI(serviceId)) {
                resourceMatch.$.attr = 'api-feature';
            }
            else {
                resourceMatch.$.attr = 'service-id';
            }
            resourceMatch.$.match= serviceId;
            policy.rule[i].condition[0]['resource-match'].push(resourceMatch);
            if (policy.rule[i].condition[0].$.combine == 'and') {
                policy.rule[i].condition[0].$.combine = 'or';
            }
            addedResourceMatch = true;
        }
    }
    if (addedResourceMatch == false) {
        // add resource failed, try to add a rule
        var rule = {};
        rule.$ = {};
        if (access == 'enable') {
            rule.$.effect = 'permit';
        } else {
            rule.$.effect = 'deny';
        }
        rule.$.id = 'r_' + Id + '_' + date;
        rule.condition = [];
        rule.condition[0] = {};
        rule.condition[0].$ = {};
        rule.condition[0].$.combine = 'or';
        rule.condition[0]['resource-match'] = [];
        rule.condition[0]['resource-match'][0] = {};
        rule.condition[0]['resource-match'][0].$ = {};
        if (isWebinosAPI(serviceId)) {
            rule.condition[0]['resource-match'][0].$.attr = 'api-feature';
        }
        else {
            rule.condition[0]['resource-match'][0].$.attr = 'service-id';
        }
        rule.condition[0]['resource-match'][0].$.match = serviceId;
        policy.rule.splice(0,0,rule);
    }
    return policy;
}

var isWebinosAPI = function(URI) {
    var exp = new RegExp ('.+(?:api|ns|manager|mwc|core)\/(?:w3c\/|api-perms\/|internal\/|discovery\/)?[^\/\.]+','');
    if (exp.exec(URI)) {
        return true;
    }
    else {
        return false;
    }
}

$(document).ready(function(){
    $("#b1").bind('click', function () {
        var user = webinos.session.getPZHId();
        if (!user) {
            user = webinos.session.getPZPId();
        }
        var service = "service1";
        getPolicy_ServiceForPeople(user, service, function(access) {
            $('#status').html('STATUS: ');
            $('#status').append(access + " access to " + service + " service by " + user);
        });
    });
    $("#b1bis").bind('click', function () {
        var user = webinos.session.getPZHId();
        if (!user) {
            user = webinos.session.getPZPId();
        }
        var service = "http://webinos.org/api/discovery";
        getPolicy_ServiceForPeople(user, service, function(access) {
            $('#status').html('STATUS: ');
            $('#status').append(access + " access to " + service + " service by " + user);
        });
    });
    $("#b2").bind('click', function () {
        var user = "friend1";
        var service = "service1";
        getPolicy_ServiceForPeople(user, service, function(access) {
            $('#status').html('STATUS: ');
            $('#status').append(access + " access to " + service + " service by " + user);
        });
    });
    $("#b3").bind('click', function () {
        var user = "friend2";
        var service = "service1";
        getPolicy_ServiceForPeople(user, service, function(access) {
            $('#status').html('STATUS: ');
            $('#status').append(access + " access to " + service + " service by " + user);
        });
    });
    $("#b4").bind('click', function () {
        var user = "friend3";
        var service = "service1";
        getPolicy_ServiceForPeople(user, service, function(access) {
            $('#status').html('STATUS: ');
            $('#status').append(access + " access to " + service + " service by " + user);
        });
    });

    $("#b5").bind('click', function () {
        var user = webinos.session.getPZHId();
        if (!user) {
            user = webinos.session.getPZPId();
        }
        getPolicy_ServicesForPeople(user, function(services) {
            $('#status').html('STATUS: ');
            for (var i = 0; i < services.length; i++) {
                $('#status').append(services[i].access + " access to " + services[i].serviceId + " service by " + user + "<br />");
            }
        });
    });
    $("#b6").bind('click', function () {
        var user = "friend1";
        getPolicy_ServicesForPeople(user, function(services) {
            $('#status').html('STATUS: ');
            for (var i = 0; i < services.length; i++) {
                $('#status').append(services[i].access + " access to " + services[i].serviceId + " service by " + user + "<br />");
            }
        });
    });
    $("#b7").bind('click', function () {
        var user = "friend2";
        getPolicy_ServicesForPeople(user, function(services) {
            $('#status').html('STATUS: ');
            for (var i = 0; i < services.length; i++) {
                $('#status').append(services[i].access + " access to " + services[i].serviceId + " service by " + user + "<br />");
            }
        });
    });
    $("#b8").bind('click', function () {
        var user = "friend3";
        getPolicy_ServicesForPeople(user, function(services) {
            $('#status').html('STATUS: ');
            for (var i = 0; i < services.length; i++) {
                $('#status').append(services[i].access + " access to " + services[i].serviceId + " service by " + user + "<br />");
            }
        });
    });

    $("#b9").bind('click', function () {
        var service = "service1";
        getPolicy_PeopleForServices(service, function(users) {
            $('#status').html('STATUS: ');
            for (var i = 0; i < users.length; i++) {
                $('#status').append("enable access to " + service + " service by " + users[i] + "<br />");
            }
        });
    });
    $("#b10").bind('click', function () {
        var service = "service2";
        getPolicy_PeopleForServices(service, function(users) {
            $('#status').html('STATUS: ');
            for (var i = 0; i < users.length; i++) {
                $('#status').append("enable access to " + service + " service by " + users[i] + "<br />");
            }
        });
    });
    $("#b11").bind('click', function () {
        var service = "service3";
        getPolicy_PeopleForServices(service, function(users) {
            $('#status').html('STATUS: ');
            for (var i = 0; i < users.length; i++) {
                $('#status').append("enable access to " + service + " service by " + users[i] + "<br />");
            }
        });
    });
    $("#b12").bind('click', function () {
        var service = "service4";
        getPolicy_PeopleForServices(service, function(users) {
            $('#status').html('STATUS: ');
            for (var i = 0; i < users.length; i++) {
                $('#status').append("enable access to " + service + " service by " + users[i] + "<br />");
            }
        });
    });
    $("#b12bis").bind('click', function () {
        var service = "http://webinos.org/api/discovery";
        getPolicy_PeopleForServices(service, function(users) {
            $('#status').html('STATUS: ');
            for (var i = 0; i < users.length; i++) {
                $('#status').append("enable access to " + service + " service by " + users[i] + "<br />");
            }
        });
    });
    $("#b12ter").bind('click', function () {
        var service = "http://webinos.org/core/policymanagement";
        getPolicy_PeopleForServices(service, function(users) {
            $('#status').html('STATUS: ');
            for (var i = 0; i < users.length; i++) {
                $('#status').append("enable access to " + service + " service by " + users[i] + "<br />");
            }
        });
    });

    $("#b13").bind('click', function () {
        var user = webinos.session.getPZHId();
        if (!user) {
            user = webinos.session.getPZPId();
        }
        var service = "service2";
        var access = "enable"
        setPolicy_ServiceForPeople(user, service, access, function(users) {
            $('#status').html('STATUS ServiceForPeople1: ');
            $('#status').append(access + " access to " + service + " service by " + user + "<br />");
        }, function(msg) {
            $('#status').html('STATUS: ');
            $('#status').append("error " + msg + "<br />");
        });
    });
    $("#b14").bind('click', function () {
        var user = webinos.session.getPZHId();
        if (!user) {
            user = webinos.session.getPZPId();
        }
        var service = "service1";
        var access = "enable"
        setPolicy_ServiceForPeople(user, service, access, function() {
            $('#status').html('STATUS ServiceForPeople2: ');
            $('#status').append(access + " access to " + service + " service by " + user + "<br />");
        }, function(msg) {
            $('#status').html('STATUS: ');
            $('#status').append("error " + msg + "<br />");
        });
    });
    $("#b15").bind('click', function () {
        var user = "friend1";
        var service = "service1";
        var access = "disable"
        setPolicy_ServiceForPeople(user, service, access, function() {
            $('#status').html('STATUS ServiceForPeople3: ');
            $('#status').append(access + " access to " + service + " service by " + user + "<br />");
        }, function(msg) {
            $('#status').html('STATUS: ');
            $('#status').append("error " + msg + "<br />");
        });
    });
    $("#b16").bind('click', function () {
        var user = "friend3";
        var service = "service1";
        var access = "enable"
        setPolicy_ServiceForPeople(user, service, access, function() {
            $('#status').html('STATUS ServiceForPeople4: ');
            $('#status').append(access + " access to " + service + " service by " + user + "<br />");
        }, function(msg) {
            $('#status').html('STATUS: ');
            $('#status').append("error " + msg + "<br />");
        });
    });
    $("#b16bis").bind('click', function () {
        var user = "friend2";
        var service = "http://webinos.org/api/discovery";
        var access = "enable"
        setPolicy_ServiceForPeople(user, service, access, function() {
            $('#status').html('STATUS ServiceForPeople5: ');
            $('#status').append(access + " access to " + service + " service by " + user + "<br />");
        }, function(msg) {
            $('#status').html('STATUS: ');
            $('#status').append("error " + msg + "<br />");
        });
    });

    $("#b17").bind('click', function () {
        var user = webinos.session.getPZHId();
        if (!user) {
            user = webinos.session.getPZPId();
        }
        var service = "service1";
        var access = "disable";
        var device = "Phone";
        setPolicy_ServiceForPeople(user, service, device, access, function(users) {
            $('#status').html('STATUS ServiceForPeople5: ');
            $('#status').append(access + " access to " + service + " service from " + device + " by " + user + "<br />");
        }, function(msg) {
            $('#status').html('STATUS: ');
            $('#status').append("error " + msg + "<br />");
        });
    });
    $("#b18").bind('click', function () {
        var user = webinos.session.getPZHId();
        if (!user) {
            user = webinos.session.getPZPId();
        }
        var service = "service2";
        var access = "enable";
        var device = "Car";
        setPolicy_ServiceForPeople(user, service, device, access, function(users) {
            $('#status').html('STATUS ServiceForPeople6: ');
            $('#status').append(access + " access to " + service + " service from " + device + " by " + user + "<br />");
        }, function(msg) {
            $('#status').html('STATUS: ');
            $('#status').append("error " + msg + "<br />");
        });
    });
    $("#b19").bind('click', function () {
        var user = "friend1";
        var service = "service3";
        var access = "enable";
        var device = "Car";
        setPolicy_ServiceForPeople(user, service, device, access, function(users) {
            $('#status').html('STATUS ServiceForPeople7: ');
            $('#status').append(access + " access to " + service + " service from " + device + " by " + user + "<br />");
        }, function(msg) {
            $('#status').html('STATUS: ');
            $('#status').append("error " + msg + "<br />");
        });
    });
    $("#b19bis").bind('click', function () {
        var user = "friend3";
        var service = "service3";
        var access = "disable";
        var device = "Car";
        setPolicy_ServiceForPeople(user, service, device, access, function(users) {
            $('#status').html('STATUS ServiceForPeople7bis: ');
            $('#status').append(access + " access to " + service + " service from " + device + " by " + user + "<br />");
        }, function(msg) {
            $('#status').html('STATUS: ');
            $('#status').append("error " + msg + "<br />");
        });
    });
    $("#b20").bind('click', function () {
        var user = "friend4";
        var service = "service1";
        var access = "enable";
        var device = "JetPlane";
        setPolicy_ServiceForPeople(user, service, device, access, function(users) {
            $('#status').html('STATUS ServiceForPeople8: ');
            $('#status').append(access + " access to " + service + " service from " + device + " by " + user + "<br />");
        }, function(msg) {
            $('#status').html('STATUS: ');
            $('#status').append("error " + msg + "<br />");
        });
    });
    $("#b20bis").bind('click', function () {
        var user = "friend2";
        var service = "http://webinos.org/api/discovery";
        var access = "enable";
        var device = "Phone";
        setPolicy_ServiceForPeople(user, service, device, access, function(users) {
            $('#status').html('STATUS ServiceForPeople9: ');
            $('#status').append(access + " access to " + service + " service from " + device + " by " + user + "<br />");
        }, function(msg) {
            $('#status').html('STATUS: ');
            $('#status').append("error " + msg + "<br />");
        });
    });

    $("#b21").bind('click', function () {
        var user = webinos.session.getPZHId();
        if (!user) {
            user = webinos.session.getPZPId();
        }
        var service = "service1";
        var device = "Phone";
        getPolicy_ServiceForPeople(user, service, device, function(access) {
            $('#status').html('STATUS: ');
            $('#status').append(access + " access to " + service + " service from " + device + " by " + user);
        });
    });
    $("#b21bis").bind('click', function () {
        var user = webinos.session.getPZHId();
        if (!user) {
            user = webinos.session.getPZPId();
        }
        var service = "http://webinos.org/api/discovery";
        var device = "Phone";
        getPolicy_ServiceForPeople(user, service, device, function(access) {
            $('#status').html('STATUS: ');
            $('#status').append(access + " access to " + service + " service from " + device + " by " + user);
        });
    });
    $("#b22").bind('click', function () {
        var user = "friend1";
        var service = "service1";
        var device = "Tablet";
        getPolicy_ServiceForPeople(user, service, device, function(access) {
            $('#status').html('STATUS: ');
            $('#status').append(access + " access to " + service + " service from " + device + " by " + user);
        });
    });
    $("#b23").bind('click', function () {
        var user = "friend2";
        var service = "service1";
        var device = "TV";
        getPolicy_ServiceForPeople(user, service, device, function(access) {
            $('#status').html('STATUS: ');
            $('#status').append(access + " access to " + service + " service from " + device + " by " + user);
        });
    });
    $("#b24").bind('click', function () {
        var user = "friend3";
        var service = "service1";
        var device = "Scooter";
        getPolicy_ServiceForPeople(user, service, device, function(access) {
            $('#status').html('STATUS: ');
            $('#status').append(access + " access to " + service + " service from " + device + " by " + user);
        });
    });

    $("#b25").bind('click', function () {
        var user = webinos.session.getPZHId();
        if (!user) {
            user = webinos.session.getPZPId();
        }
        var device = "Car";
        getPolicy_ServicesForPeople(user, device, function(services) {
            $('#status').html('STATUS: ');
            for (var i = 0; i < services.length; i++) {
                $('#status').append(services[i].access + " access to " + services[i].serviceId + " service from " + device + " by " + user + "<br />");
            }
        });
    });
    $("#b26").bind('click', function () {
        var user = "friend1";
        var device = "TV";
        getPolicy_ServicesForPeople(user, device, function(services) {
            $('#status').html('STATUS: ');
            for (var i = 0; i < services.length; i++) {
                $('#status').append(services[i].access + " access to " + services[i].serviceId + " service from " + device + " by " + user + "<br />");
            }
        });
    });
    $("#b27").bind('click', function () {
        var user = "friend2";
        var device = "Laptop";
        getPolicy_ServicesForPeople(user, device, function(services) {
            $('#status').html('STATUS: ');
            for (var i = 0; i < services.length; i++) {
                $('#status').append(services[i].access + " access to " + services[i].serviceId + " service from " + device + " by " + user + "<br />");
            }
        });
    });
    $("#b28").bind('click', function () {
        var user = "friend3";
        var device = "Phone";
        getPolicy_ServicesForPeople(user, device, function(services) {
            $('#status').html('STATUS: ');
            for (var i = 0; i < services.length; i++) {
                $('#status').append(services[i].access + " access to " + services[i].serviceId + " service from " + device + " by " + user + "<br />");
            }
        });
    });

    $("#b29").bind('click', function () {
        var service = "service1";
        var device = "Phone";
        getPolicy_PeopleForServices(service, device, function(users) {
            $('#status').html('STATUS: ');
            for (var i = 0; i < users.length; i++) {
                $('#status').append("enable access to " + service + " service from " + device + " by " + users[i] + "<br />");
            }
        });
    });
    $("#b29bis").bind('click', function () {
        var service = "http://webinos.org/api/discovery";
        var device = "Phone";
        getPolicy_PeopleForServices(service, device, function(users) {
            $('#status').html('STATUS: ');
            for (var i = 0; i < users.length; i++) {
                $('#status').append("enable access to " + service + " service from " + device + " by " + users[i] + "<br />");
            }
        });
    });
    $("#b29ter").bind('click', function () {
        var service = "http://webinos.org/core/policymanagement";
        var device = "Phone";
        getPolicy_PeopleForServices(service, device, function(users) {
            $('#status').html('STATUS: ');
            for (var i = 0; i < users.length; i++) {
                $('#status').append("enable access to " + service + " service from " + device + " by " + users[i] + "<br />");
            }
        });
    });
    $("#b30").bind('click', function () {
        var service = "service2";
        var device = "Car";
        getPolicy_PeopleForServices(service, device, function(users) {
            $('#status').html('STATUS: ');
            for (var i = 0; i < users.length; i++) {
                $('#status').append("enable access to " + service + " service from " + device + " by " + users[i] + "<br />");
            }
        });
    });
    $("#b31").bind('click', function () {
        var service = "service3";
        var device = "Laptop";
        getPolicy_PeopleForServices(service, device, function(users) {
            $('#status').html('STATUS: ');
            for (var i = 0; i < users.length; i++) {
                $('#status').append("enable access to " + service + " service from " + device + " by " + users[i] + "<br />");
            }
        });
    });
    $("#b32").bind('click', function () {
        var service = "service4";
        var device = "TV";
        getPolicy_PeopleForServices(service, device, function(users) {
            $('#status').html('STATUS: ');
            for (var i = 0; i < users.length; i++) {
                $('#status').append("enable access to " + service + " service from " + device + " by " + users[i] + "<br />");
            }
        });
    });

});

