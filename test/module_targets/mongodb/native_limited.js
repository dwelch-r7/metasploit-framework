// Invoked in a fresh shell authenticated only as the database-scoped account.
var marker = db.getSiblingDB('intranet').evidence.findOne({name: 'module-target-mongodb'}).marker;
var result;
try {
  result = db.getSiblingDB('admin').runCommand({find: 'system.users', filter: {}, limit: 1});
} catch (error) {
  result = {ok: 0, code: error.code, errmsg: error.message};
}
print('MONGODB_LIMITED=' + JSON.stringify({marker: marker, system_users: result}));
