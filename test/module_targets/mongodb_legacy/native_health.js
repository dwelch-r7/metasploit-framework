var adminDb = db.getSiblingDB('admin');
if (!adminDb.auth('rootuser', 'rootpass')) { throw new Error('Native root authentication failed'); }
if (db.getSiblingDB('intranet').evidence.findOne().marker !== 'native-mongodb-proof') { throw new Error('Native evidence row is incorrect'); }
if (db.getSiblingDB('intranet').app_users.count() !== 111) { throw new Error('Native cursor fixture count is incorrect'); }
print('Native legacy MongoDB authentication and fixture verified: ' + db.version());
