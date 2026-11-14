require 'rspec'
require 'msfenv'
require 'msf/base'
require 'sqlite3'
require 'tmpdir'
require 'base64'
require 'digest'
require 'openssl'

RSpec.describe 'Ni8mare JWT and extracted hash contracts' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('NI8MARE_JWT_OWNER_SOURCE', File.expand_path('../../../../modules/auxiliary/gather/ni8mare_cve_2026_21858.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:fixture_hash) { '$2b$10$012345678901234567890uFjb.PbJYfwIgHMpshhET0VQlt8t.SD6' }
  let(:target_email) { 'module.native1@example.test' }
  let(:encryption_key) { '0123456789abcdef' }
  let(:messages) { [] }
  let(:loot) { [] }
  let(:credentials) { [] }
  let(:validated_credentials) { [] }
  let(:logins) { [] }
  let(:opened_databases) { [] }
  let(:read_paths) { [] }
  let(:source_path) { File.join(@unit_directory, 'source.sqlite') }
  let(:database_loot_path) { File.join(@unit_directory, 'database.sqlite') }
  let(:binary_content) { "\x00\xff\x80n8n\n".b }

  around do |example|
    Dir.mktmpdir('ni8mare-jwt-contracts') do |directory|
      @unit_directory = directory
      # Deterministic lab-only hashes/emails from root's genuine jwt-fixtures.json.
      # UUIDs are local row identifiers; no application identity is simulated.
      SQLite3::Database.open(source_path) do |db|
        db.execute('CREATE TABLE user (id TEXT, email TEXT, password TEXT)')
        db.execute('INSERT INTO user VALUES (?, ?, ?)', ['00000000-0000-4000-8000-000000000001', 'module.native1@example.test', fixture_hash])
        db.execute('INSERT INTO user VALUES (?, ?, ?)', ['00000000-0000-4000-8000-000000000002', 'module.native3@example.test', fixture_hash])
        db.execute('INSERT INTO user VALUES (?, ?, ?)', ['00000000-0000-4000-8000-000000000003', 'module.native0@example.test', fixture_hash])
      end
      example.run
    ensure
      if (path = ENV['NI8MARE_JWT_UNIT_EVIDENCE'])
        record = {
          example: example.full_description,
          tickets: messages.grep(/\AJWT ticket as /),
          credentials: credentials,
          validated_credentials: validated_credentials,
          login_reports: logins,
          opened_database_closed: opened_databases.map { |entry| { path: entry[:path], closed: entry[:handle].closed? } }
        }
        File.open(path, 'a') { |file| file.puts(JSON.generate(record)) }
      end
      # Preserve the observed open/closed evidence before cleaning old-source handles.
      opened_databases.each { |entry| entry[:handle].close unless entry[:handle].closed? }
    end
  end

  before do
    mod.datastore.merge!(
      'RHOSTS' => '192.0.2.10', 'RPORT' => 5678,
      'USERNAME' => 'reader@example.test', 'PASSWORD' => 'controlled-lab-password',
      'TARGET_EMAIL' => target_email, 'N8N_CONFIG_DIR' => '/home/node/.n8n'
    )
    # Authentication, workflow/file extraction and Framework reporting/storage are
    # doubles. SQLite bytes/queries/handles, claim derivation and JWT/HMAC are real.
    allow(mod).to receive(:login).and_return(true)
    allow(mod).to receive(:myworkspace_id).and_return(17)
    allow(mod).to receive(:print_good) { |message| messages << message }
    allow(mod).to receive(:create_credential) { |data| credentials << data }
    allow(mod).to receive(:store_valid_credential) { |data| validated_credentials << data }
    allow(mod).to receive(:create_credential_login) { |data| logins << data }
    allow(mod).to receive(:create_credential_and_login) { |data| logins << data }
    allow(mod).to receive(:read_file) do |path|
      read_paths << path
      case path
      when '/home/node/.n8n/database.sqlite'
        File.binread(source_path)
      when '/home/node/.n8n/config'
        JSON.generate('encryptionKey' => encryption_key)
      when '/tmp/ni8mare-proof.bin'
        binary_content
      else
        raise ArgumentError, "Unexpected file extraction: #{path}"
      end
    end
    allow(mod).to receive(:store_loot) do |type, content_type, host, content|
      loot << { type: type, content_type: content_type, host: host, content: content }
      name = case type
             when 'database.sqlite' then 'database.sqlite'
             when 'n8n.config' then 'config.json'
             else 'proof.bin'
             end
      File.join(@unit_directory, name).tap { |path| File.binwrite(path, content) }
    end
    allow(SQLite3::Database).to receive(:new).and_wrap_original do |original, *arguments, &block|
      original.call(*arguments, &block).tap do |database|
        opened_databases << { path: arguments.first, handle: database }
      end
    end
  end

  def ticket
    messages.find { |message| message.start_with?('JWT ticket as ') }.split(': ', 2).last
  end

  def extracted_database_handles
    opened_databases.select { |entry| entry[:path] == database_loot_path }.map { |entry| entry[:handle] }
  end

  shared_examples 'a native user hash claim' do |expected_claim, expected_id|
    it 'emits the genuine claim in a correctly signed Base64url JWT envelope' do
      mod.run
      header, payload, signature = ticket.split('.')

      expect(JSON.parse(Base64.urlsafe_decode64(header))).to eq('alg' => 'HS256', 'typ' => 'JWT')
      expect(JSON.parse(Base64.urlsafe_decode64(payload))).to eq('id' => expected_id, 'hash' => expected_claim)
      expect([header, payload, signature]).to all(match(/\A[A-Za-z0-9_-]+\z/))
      # JwtService uses every second encryption-key character, then SHA256 hex.
      signing_key = Digest::SHA256.hexdigest('02468ace')
      expect(Base64.urlsafe_decode64(signature)).to eq(OpenSSL::HMAC.digest('SHA256', signing_key, "#{header}.#{payload}"))
    end
  end

  context 'ordinary native fixture' do
    include_examples 'a native user hash claim', 'KC0EjZbZAH', '00000000-0000-4000-8000-000000000001'
  end

  context 'native fixture whose claim contains plus' do
    let(:target_email) { 'module.native3@example.test' }

    include_examples 'a native user hash claim', 'eqdYW+IeRu', '00000000-0000-4000-8000-000000000002'
  end

  context 'native fixture whose claim contains slash' do
    let(:target_email) { 'module.native0@example.test' }

    include_examples 'a native user hash claim', '/PUplRmvUX', '00000000-0000-4000-8000-000000000003'
  end

  it 'records the extracted bcrypt hash with its import origin and Framework hash format' do
    mod.run

    expect(credentials).to eq([
      {
        origin_type: :import, filename: database_loot_path, workspace_id: 17,
        username: target_email, private_data: fixture_hash,
        private_type: :nonreplayable_hash, jtr_format: 'bf'
      }
    ])
  end

  it 'does not claim the hash authenticated as a plaintext password or create a successful login' do
    mod.run

    expect(validated_credentials + logins).to be_empty
  end

  it 'closes the actual extracted SQLite database before returning the ticket' do
    mod.run

    expect(extracted_database_handles.length).to eq(1)
    expect(extracted_database_handles).to all(be_closed)
  end

  it 'retains the exact extracted database as loot and uses the default key-derivation path' do
    database_bytes = File.binread(source_path)
    mod.run

    expect(File.binread(database_loot_path)).to eq(database_bytes)
    expect(read_paths).to eq(['/home/node/.n8n/database.sqlite', '/home/node/.n8n/config'])
  end

  context 'when the selected user is absent' do
    let(:target_email) { 'missing@example.test' }

    it 'closes the database and preserves NotFound without a hash or ticket report' do
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, 'not-found: Could not found missing@example.test in database')
      expect(extracted_database_handles).to all(be_closed)
      expect(credentials + validated_credentials + messages.grep(/\AJWT ticket as /)).to be_empty
    end
  end

  context 'when querying the extracted database fails' do
    before do
      SQLite3::Database.open(source_path) { |db| db.execute('DROP TABLE user') }
    end

    it 'closes the actual handle and reports a concise UnexpectedReply' do
      expect(mod).to receive(:elog).with('Failed to read user credentials from the extracted n8n database', error: be_a(SQLite3::SQLException))
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, 'unexpected-reply: Failed to read user credentials from the extracted n8n database.')
      expect(extracted_database_handles.length).to eq(1)
      expect(extracted_database_handles).to all(be_closed)
    end
  end

  context 'when subsequent config extraction fails' do
    before do
      allow(mod).to receive(:read_file).with('/home/node/.n8n/config').and_return(nil)
    end

    it 'already closed the extracted database before the later failure' do
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, 'not-found: Could not found config file')
      expect(extracted_database_handles.length).to eq(1)
      expect(extracted_database_handles).to all(be_closed)
      expect(messages.grep(/\AJWT ticket as /)).to be_empty
    end
  end

  context 'READ_FILE action' do
    before do
      mod.datastore['ACTION'] = 'READ_FILE'
      mod.datastore['TARGET_FILENAME'] = '/tmp/ni8mare-proof.bin'
    end

    it 'preserves exact binary loot without deriving a token or reporting a hash' do
      mod.run

      expect(loot).to eq([{ type: '/tmp/ni8mare-proof.bin', content_type: 'text/plain', host: '192.0.2.10', content: binary_content }])
      expect(credentials + validated_credentials + opened_databases + messages.grep(/\AJWT ticket as /)).to be_empty
    end
  end

  it 'preserves public action and option names without adding TARGETURI' do
    expect(mod.action.name).to eq('EXTRACT_SESSION')
    expect(mod.options.keys).to include('TARGET_EMAIL', 'N8N_CONFIG_DIR', 'TARGET_FILENAME', 'USERNAME', 'PASSWORD')
    expect(mod.options.keys).not_to include('TARGETURI')
  end
end
