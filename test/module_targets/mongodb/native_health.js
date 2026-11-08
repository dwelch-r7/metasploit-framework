var adminDb = db.getSiblingDB('admin');
if (!adminDb.auth('rootuser', 'rootpass')) { throw new Error('Native root authentication failed'); }
var intranet = db.getSiblingDB('intranet');
if (intranet.evidence.findOne({name: 'module-target-mongodb'}).marker !== 'native-mongodb-proof') {
  throw new Error('Native evidence row is incorrect');
}
if (intranet.app_users.countDocuments({}) !== 111) { throw new Error('Native cursor fixture count is incorrect'); }
if (adminDb.system.users.find({user: 'rootuser'}).count() !== 1) { throw new Error('Native system user is missing'); }
print('Native MongoDB authentication, row and cursor fixture verified: ' + db.version());
