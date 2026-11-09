# frozen_string_literal: true

require 'base64'
require_relative '../couchdb/native_client'

host, port, profile = ARGV
raise ArgumentError, 'Unknown native legacy profile' unless %w[open auth].include?(profile)

client = CouchDBNativeClient.new(host, port, credentials: profile == 'auth' ? CouchDBNativeClient::DEFAULT_CREDENTIALS : nil)
request = client.method(:request)
code, version = request.call('get', '/')
raise 'Native legacy version differs' unless code == 200 && version.fetch('version') == '1.6.1'

%w[_users _replicator module_evidence].each do |database|
  code, = request.call('put', "/#{database}")
  raise "Native legacy initialization failed: #{database}" unless [201, 202, 412].include?(code)
end
reader_data = { 'name' => 'labreader', 'type' => 'user', 'roles' => [], 'password' => 'readerpassword' }
code, = request.call('put', '/_users/org.couchdb.user:labreader', reader_data)
raise 'Native legacy reader initialization failed' unless [201, 202, 409].include?(code)

document = {
  'marker' => 'legacy-couchdb-proof', 'nested' => { 'value' => 42 },
  '_attachments' => {
    'proof.txt' => { 'content_type' => 'text/plain', 'data' => Base64.strict_encode64("legacy-attachment-proof\n") },
    'proof.bin' => { 'content_type' => 'application/octet-stream', 'data' => Base64.strict_encode64("legacy-binary-proof\x00\xff".b) }
  }
}
code, = request.call('put', '/module_evidence/proof-one', document)
raise 'Native legacy document initialization failed' unless [201, 202, 409].include?(code)

code, identity = request.call('get', '/_session')
raise 'Native legacy session failed' unless code == 200

if profile == 'auth' && identity.fetch('userCtx').slice('name', 'roles') != { 'name' => 'labadmin', 'roles' => ['_admin'] }
  raise 'Native legacy administrator identity differs'
end

code, reader = request.call('get', '/_session', nil, %w[labreader readerpassword])
raise 'Native legacy reader identity differs' unless code == 200 && reader.fetch('userCtx').fetch('name') == 'labreader'

code, = request.call('get', '/_session', nil, %w[labreader wrong-password])
raise 'Native legacy wrong password accepted' unless code == 401

code, databases = request.call('get', '/_all_dbs', nil, nil)
raise 'Native legacy anonymous listing differs' unless code == 200 && databases.include?('module_evidence')

code, documents = request.call('get', '/module_evidence/_all_docs?include_docs=true&attachments=true')
raise 'Native legacy document retrieval failed' unless code == 200 && documents.fetch('total_rows') == 1

first = documents.fetch('rows').first.fetch('doc')
raise 'Native legacy document differs' unless first.fetch('marker') == 'legacy-couchdb-proof'
raise 'Native legacy attachment differs' unless Base64.strict_decode64(first.fetch('_attachments').fetch('proof.txt').fetch('data')) == "legacy-attachment-proof\n"
raise 'Native legacy binary attachment differs' unless Base64.strict_decode64(first.fetch('_attachments').fetch('proof.bin').fetch('data')) == "legacy-binary-proof\x00\xff".b

bypass = nil
if profile == 'auth'
  user_path = '/_users/org.couchdb.user:native_role_probe'
  payload = '{"type":"user","name":"native_role_probe","roles":["_admin"],"roles":[],"password":"native-role-password"}'
  revision = nil
  begin
    code, created = request.call('put', user_path, payload, nil)
    raise 'Native duplicate-role creation failed' unless code == 201 && created.fetch('ok')

    revision = created.fetch('rev')
    code, bypass = request.call('get', '/_session', nil, %w[native_role_probe native-role-password])
    raise 'Native duplicate-role elevation failed' unless code == 200 && bypass.fetch('userCtx').slice('name', 'roles') == { 'name' => 'native_role_probe', 'roles' => ['_admin'] }
  ensure
    if revision
      code, removed = request.call('delete', "#{user_path}?rev=#{revision}")
      raise 'Native role-probe cleanup failed' unless [200, 202].include?(code) && removed.fetch('ok')
    end
  end
  code, = request.call('get', user_path)
  raise 'Native role-probe account remains' unless code == 404
end

puts JSON.generate(version: version, profile: profile, databases: databases, documents: documents,
                   identity: identity, reader: reader, bypass: bypass, commands: client.commands)
