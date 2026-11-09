var marker = db.getSiblingDB('intranet').evidence.findOne().marker;
var result = db.getSiblingDB('admin').runCommand({count: 'system.users'});
print('MONGODB_LIMITED=' + JSON.stringify({marker: marker, system_users: result}));
