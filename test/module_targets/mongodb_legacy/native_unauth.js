print('MONGODB_POLICY=' + JSON.stringify(db.getSiblingDB('intranet').runCommand({count: 'evidence'})));
