var adminDb = db.getSiblingDB('admin');
adminDb.createUser({user: 'rootuser', pwd: 'rootpass', roles: [{role: 'root', db: 'admin'}]});
var intranet = db.getSiblingDB('intranet');
intranet.createUser({user: 'testuser', pwd: 'testpass', roles: [{role: 'readWrite', db: 'intranet'}]});
intranet.evidence.insert({name: 'module-target-mongodb', marker: 'native-mongodb-proof'});
var rows = [];
for (var index = 0; index < 111; index++) {
  rows.push({username: 'app-user-' + index, hash: 'd41d8cd98f00b204e9800998ecf8427e'});
}
intranet.app_users.insert(rows);
