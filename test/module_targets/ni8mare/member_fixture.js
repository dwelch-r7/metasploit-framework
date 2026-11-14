// Fixture data follows the installed UserRepository.createUserWithProject
// relationship contract. Real login and workflow APIs must verify its behavior.
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const root = path.dirname(path.dirname(fs.realpathSync('/usr/local/bin/n8n')));
const bcrypt = require(root + '/node_modules/bcryptjs');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const database = new DatabaseSync('/home/node/.n8n/database.sqlite');
database.exec('PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000');
const member = {
  id: '00000000-0000-4000-8000-000000000002',
  project_id: '00000000-0000-4000-8000-000000000003',
  email: 'module.reader@example.test',
  password: 'ModuleTarget-reader-456!',
};
function insert(table, values) {
  const columns = Object.keys(values);
  const names = columns.map(name => '"' + name.replaceAll('"', '""') + '"');
  const placeholders = columns.map(() => '?');
  database.prepare('INSERT INTO "' + table + '" (' + names.join(',') + ') VALUES (' + placeholders.join(',') + ')')
    .run(...columns.map(name => values[name]));
}
if (input.action === 'create') {
  const owner = database.prepare('SELECT * FROM user WHERE id=?').get(input.owner_id);
  if (!owner || owner.roleSlug !== 'global:owner') throw Error('Fixture owner is unavailable');
  const relation = database.prepare('SELECT * FROM project_relation WHERE userId=? AND role=?')
    .get(owner.id, 'project:personalOwner');
  if (!relation) throw Error('Fixture owner personal project is unavailable');
  const project = database.prepare('SELECT * FROM project WHERE id=?').get(relation.projectId);
  const user = {
    ...owner,
    id: member.id,
    email: member.email,
    firstName: 'Module',
    lastName: 'Reader',
    password: bcrypt.hashSync(member.password, '$2b$10$012345678901234567890u'),
    disabled: 0,
    mfaEnabled: 0,
    mfaSecret: null,
    mfaRecoveryCodes: null,
    roleSlug: 'global:member',
  };
  database.exec('BEGIN');
  try {
    insert('user', user);
    insert('project', { ...project, id: member.project_id, name: 'Module Reader <' + member.email + '>', type: 'personal' });
    insert('project_relation', { ...relation, projectId: member.project_id, userId: member.id, role: 'project:personalOwner' });
    database.exec('COMMIT');
  } catch (error) {
    database.exec('ROLLBACK');
    throw error;
  }
} else if (input.action === 'remove') {
  if (database.prepare('SELECT count(*) AS count FROM workflow_entity').get().count !== 0) {
    throw Error('Workflows remain before member fixture removal');
  }
  database.exec('BEGIN');
  try {
    database.prepare('DELETE FROM project_relation WHERE projectId=? AND userId=?').run(member.project_id, member.id);
    database.prepare('DELETE FROM project WHERE id=?').run(member.project_id);
    database.prepare('DELETE FROM user WHERE id=?').run(member.id);
    database.exec('COMMIT');
  } catch (error) {
    database.exec('ROLLBACK');
    throw error;
  }
} else {
  throw Error('Unknown member fixture action');
}
database.close();
console.log(JSON.stringify(member));
