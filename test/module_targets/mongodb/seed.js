// Public fixture users; application hashes use the MD5 of an empty string.
var adminDb = db.getSiblingDB('admin');
adminDb.createUser({user: 'rootuser', pwd: 'rootpass', roles: [{role: 'root', db: 'admin'}]});
var intranet = db.getSiblingDB('intranet');
intranet.createUser({user: 'testuser', pwd: 'testpass', roles: [{role: 'readWrite', db: 'intranet'}]});
intranet.evidence.insertMany([
  {name: 'module-target-mongodb', marker: 'native-mongodb-proof', count: 42, enabled: true, nested: {kind: 'fixture'}},
  {name: 'second-record', marker: 'second-mongodb-proof', count: 7, enabled: false, tags: ['one', 'two']}
]);
intranet.createCollection('empty_evidence');
var hashes = [];
for (var index = 0; index < 111; index++) {
  hashes.push({username: 'app-user-' + index, hash: 'd41d8cd98f00b204e9800998ecf8427e'});
}
intranet.app_users.insertMany(hashes);
