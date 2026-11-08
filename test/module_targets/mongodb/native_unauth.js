// A fresh shell connection proves enforcement before any successful login.
var result;
try {
  result = db.getSiblingDB('intranet').runCommand({find: 'evidence', filter: {name: 'module-target-mongodb'}, limit: 1});
} catch (error) {
  result = {ok: 0, code: error.code, errmsg: error.message};
}
print('MONGODB_POLICY=' + JSON.stringify(result));
