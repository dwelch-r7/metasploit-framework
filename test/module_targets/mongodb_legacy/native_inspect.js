var adminDb = db.getSiblingDB('admin');
if (!adminDb.auth('rootuser', 'rootpass')) { throw new Error('Native root authentication failed'); }
var intranet = db.getSiblingDB('intranet');
print('MONGODB_NATIVE=' + JSON.stringify({
  version: db.version(),
  users: adminDb.system.users.find({}, {_id: 0, user: 1, db: 1, credentials: 1, pwd: 1}).toArray(),
  evidence: intranet.evidence.find({}, {_id: 0}).toArray(),
  app_count: intranet.app_users.count(),
  app_first: intranet.app_users.findOne({username: 'app-user-0'}, {_id: 0})
}));
