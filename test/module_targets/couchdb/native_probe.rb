# frozen_string_literal: true

require 'base64'
require 'json'
require_relative 'native_client'

host, port = ARGV
client = CouchDBNativeClient.new(host, port)
request = client.method(:request)

status, version = request.call('get', '/')
raise 'Native CouchDB version differs' unless status == 200 && version.fetch('version') == '3.3.1'

%w[_users _replicator _global_changes module_evidence].each do |database|
  code, = request.call('put', "/#{database}")
  raise "Native database initialization failed: #{database}" unless [201, 202, 412].include?(code)
end
user = { 'name' => 'labreader', 'type' => 'user', 'roles' => [], 'password' => 'readerpassword' }
code, = request.call('put', '/_users/org.couchdb.user:labreader', user)
raise 'Native reader initialization failed' unless [201, 202, 409].include?(code)

document = {
  '_id' => 'proof-one', 'marker' => 'native-couchdb-proof', 'nested' => { 'value' => 42 },
  '_attachments' => {
    'proof.txt' => { 'content_type' => 'text/plain', 'data' => Base64.strict_encode64("native-attachment-proof\n") },
    'proof.bin' => { 'content_type' => 'application/octet-stream', 'data' => Base64.strict_encode64("native-binary-proof\x00\xff".b) }
  }
}
code, = request.call('put', '/module_evidence/proof-one', document)
raise 'Native document initialization failed' unless [201, 202, 409].include?(code)

code, = request.call('put', '/module_evidence/proof-two', { 'marker' => 'second-native-proof', 'enabled' => true })
raise 'Native second document initialization failed' unless [201, 202, 409].include?(code)

code, administrator = request.call('get', '/_session')
raise 'Native administrator authentication failed' unless code == 200 && administrator.fetch('userCtx').fetch('roles').include?('_admin')

code, = request.call('get', '/_session', nil, ['labadmin', 'wrong-password'])
raise 'Native wrong password was accepted' unless code == 401

code, reader = request.call('get', '/_session', nil, ['labreader', 'readerpassword'])
raise 'Native reader authentication failed' unless code == 200 && reader.fetch('userCtx').fetch('name') == 'labreader'

code, = request.call('get', '/_users/_all_docs', nil, ['labreader', 'readerpassword'])
raise 'Native reader unexpectedly lists user documents' unless code == 401

code, = request.call('get', '/_all_dbs', nil, nil)
raise 'Native anonymous database listing was accepted' unless code == 401

code, databases = request.call('get', '/_all_dbs')
raise 'Native database listing differs' unless code == 200 && databases.include?('module_evidence')

code, documents = request.call('get', '/module_evidence/_all_docs?include_docs=true&attachments=true')
raise 'Native document listing differs' unless code == 200 && documents.fetch('total_rows') == 2

first = documents.fetch('rows').find { |row| row.fetch('id') == 'proof-one' }.fetch('doc')
raise 'Native document contents differ' unless first.fetch('marker') == 'native-couchdb-proof'
raise 'Native attachment contents differ' unless Base64.strict_decode64(first.fetch('_attachments').fetch('proof.txt').fetch('data')) == "native-attachment-proof\n"
raise 'Native binary attachment differs' unless Base64.strict_decode64(first.fetch('_attachments').fetch('proof.bin').fetch('data')) == "native-binary-proof\x00\xff".b

puts JSON.generate(version: version, databases: databases, documents: documents, administrator: administrator, reader: reader, commands: client.commands)
