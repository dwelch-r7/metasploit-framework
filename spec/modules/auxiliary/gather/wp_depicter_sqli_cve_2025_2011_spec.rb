require 'rspec'
require 'msfenv'
require 'msf/base'
require 'metasploit/framework/hashes'

RSpec.describe 'Depicter SQL injection contracts' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('DEPICTER_OWNER_SOURCE', File.expand_path('../../../../modules/auxiliary/gather/wp_depicter_sqli_cve_2025_2011.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:captures) { JSON.parse(File.read(File.expand_path('../../../file_fixtures/modules/auxiliary/gather/wp_depicter_sqli_cve_2025_2011/responses.json', __dir__))).fetch('responses') }
  let(:framework) { double('Framework', datastore: Msf::DataStore.new) }
  let(:profile) { { 'ajax' => '/wp-admin/admin-ajax.php' } }
  let(:query_reply) { :modeled }
  let(:table_prefix) { 'wp_' }
  let(:prefix_miss) { nil }
  let(:group_limit) { 65_535 }
  let(:incomplete_row) { false }
  let(:missing_dump_scalar) { false }
  let(:malformed_hex) { nil }
  let(:invalid_row_count) { false }
  # Inert synthetic values have the native 63-byte hash length, not real hashes.
  let(:hash_value) { '$wp$2y$10$' + ('a' * 53) }
  let(:rows) { %w[module_admin module_author module_reader module_editor].map { |username| [username, hash_value] } }
  let(:requests) { [] }
  let(:queries) { [] }
  let(:credentials) { [] }
  let(:loot) { [] }
  let(:reports) { [] }
  let(:lines) { [] }

  before do
    mod.datastore.merge!('RHOSTS' => '192.0.2.10', 'RHOST' => '192.0.2.10', 'RPORT' => 80, 'SSL' => false, 'AutoCheck' => false)
    allow(mod).to receive(:framework).and_return(framework)
    allow(mod).to receive(:user_output).and_return(Rex::Ui::Text::Output::Buffer.new)
    allow(mod).to receive(:myworkspace_id).and_return(1)
    allow(mod).to receive(:create_credential) { |data| credentials << data }
    allow(mod).to receive(:store_loot) do |*arguments|
      loot << arguments
      '/unit/wordpress-users.txt'
    end
    %i[report_host report_service report_vuln].each { |method| allow(mod).to receive(method) { |*arguments| reports << [method, arguments] } }
    allow(mod).to receive(:print_line) { |text| lines << text }
    %i[print_status print_good print_error print_warning vprint_status vprint_good vprint_error elog].each { |method| allow(mod).to receive(method) }
    allow(mod).to receive(:rand).and_call_original
    allow(mod).to receive(:rand).with(0..19).and_return(0)
    # HTTP, UI, persistence and the bounded SQL evaluator are doubles. Real
    # Common SQL generation/decoding, WordPress prefix discovery, reporting
    # arguments and AutoCheck execute. No native/database qualification follows.
    allow(mod).to receive(:send_request_cgi) do |options|
      requests << options
      if options['uri'] != profile['ajax']
        reply(404, 'Not Found')
      elsif query_reply == :modeled
        sql_response(options)
      else
        query_reply
      end
    end
  end

  def reply(code, body = '')
    Rex::Proto::Http::Response.new(code).tap { |result| result.body = body }
  end

  def response(name)
    data = captures.fetch(name)
    reply(data.fetch('code'), data.fetch('body'))
  end

  def scalar(value)
    document = JSON.parse(captures.fetch('scalar').fetch('body'))
    document.fetch('hits').first.fetch('content')['id'] = value
    reply(200, JSON.generate(document))
  end

  def sql_response(options)
    injection = options.fetch('vars_get').fetch('s')
    sql = injection[/\A\d+'\) UNION SELECT \d+,\d+,\((.*)\),\d+,\d+-- -\z/m, 1]
    raise ArgumentError, 'Unexpected unit injection envelope' unless sql

    queries << sql
    if (match = sql.match(/\Aselect hex\(0x([0-9a-f]+)\)\z/i))
      scalar(match[1].upcase)
    elsif (match = sql.match(/\Aselect 0x([0-9a-f]+)\z/i))
      scalar([match[1]].pack('H*'))
    elsif sql.include?('information_schema.tables') && sql.match?(/\ASELECT \d+/)
      scalar(table_prefix == 'wp_' ? sql[/\ASELECT (\d+)/, 1] : prefix_miss)
    elsif sql.start_with?('SELECT LEFT(table_name')
      scalar(table_prefix)
    elsif (match = sql.match(/\Aselect count\(1\) from (\w+users)\z/i))
      return response('empty') unless match[1] == table_prefix + 'users'

      value = missing_dump_scalar ? nil : rows.length.to_s
      scalar(invalid_row_count ? 'not-a-count' : value)
    elsif (match = sql.match(/from (\w+users) limit (\d+),1\z/i))
      return response('empty') unless match[1] == table_prefix + 'users'

      fields = rows.fetch(match[2].to_i)
      fields = fields.first(1) if incomplete_row && match[2] == '1'
      return scalar([fields.first.b.unpack1('H*'), malformed_hex].join(';')) if malformed_hex && match[2] == '1'

      scalar(fields.map { |field| sql.include?('hex(') ? field.b.unpack1('H*').upcase : field }.join(';'))
    elsif sql.include?('group_concat')
      return scalar(nil) if missing_dump_scalar
      return response('empty') unless sql.include?(" from #{table_prefix}users")

      limit = sql[/from \w+users limit (\d+)/i, 1]
      selected = limit ? rows.first(limit.to_i) : rows
      selected = selected.each_with_index.map { |row_values, index| incomplete_row && index == 1 ? row_values.first(1) : row_values }
      scalar(selected.map { |row_values| row_values.join(';') }.join(',').b.byteslice(0, group_limit))
    else
      raise ArgumentError, "Unexpected unit SQL query: #{sql}"
    end
  end

  def rejected(reason)
    expect { mod.run }.to raise_error(Msf::Auxiliary::Failed)
    expect(mod.fail_reason).to eq(reason)
    expect(credentials).to be_empty
    expect(loot).to be_empty
    expect(reports).to be_empty
  end

  it 'proves injection by matching the real Common scalar canary' do
    expect(mod.check).to have_attributes(code: 'vulnerable', reason: 'SQL injection test succeeded')
    expect(credentials).to be_empty
  end

  it 'registers the documented integer COUNT with default one' do
    expect(mod.options['COUNT']).to be_a(Msf::OptInt)
    expect(mod.datastore['COUNT']).to eq(1)
  end

  { 1 => 1, 0 => 4, 2 => 2 }.each do |count, expected|
    it "retains exact credentials and loot with COUNT #{count}" do
      mod.datastore['COUNT'] = count
      mod.run
      expect(credentials.map { |data| [data[:username], data[:private_data]] }).to eq(rows.first(expected))
      expect(credentials).to all(include(private_type: :nonreplayable_hash, service_name: 'WordPress', address: '192.0.2.10'))
      expect(loot.first.fetch(3)).to eq(rows.first(expected).map { |username, hash| "Username: #{username}, Password Hash: #{hash}\n" }.join)
    end
  end

  it 'rejects negative COUNT before collection' do
    mod.datastore['COUNT'] = -1
    rejected(Msf::Module::Failure::BadConfig)
  end

  context 'with the genuine WordPress subdirectory' do
    before do
      profile['ajax'] = '/wordpress/wp-admin/admin-ajax.php'
      mod.datastore['TARGETURI'] = '/wordpress/'
    end

    it('checks the configured installation') { expect(mod.check.code).to eq('vulnerable') }
    it 'collects from its actual AJAX endpoint' do
      mod.run
      expect(credentials.first[:private_data]).to eq(hash_value)
      expect(requests.map { |request| request['uri'] }.uniq).to eq(['/wordpress/wp-admin/admin-ajax.php'])
    end
  end

  it 'does not scan the root installation when TARGETURI is missing' do
    mod.datastore['TARGETURI'] = '/module-target-missing/'
    expect(mod.check).to have_attributes(code: 'unknown', reason: a_string_matching(/404/))
  end

  context 'with the native 96-byte aggregation limit' do
    let(:group_limit) { 96 }

    [0, 2].each do |count|
      it "retrieves complete hashes with COUNT #{count} and AutoCheck disabled" do
        mod.datastore['COUNT'] = count
        mod.run
        expect(credentials.map { |data| data[:private_data] }).to eq([hash_value] * (count.zero? ? 4 : count))
      end
    end
  end

  context 'with synthetic delimiter and UTF-8 username bytes' do
    let(:rows) { [['owned,semi;é雪', hash_value]] }

    it 'preserves field bytes through HEX decoding' do
      mod.run
      expect(credentials.map { |data| [data[:username].b, data[:private_data].b] }).to eq(rows.map { |row| row.map(&:b) })
    end
  end

  context 'with a synthetic custom table prefix and SQL NULL default miss' do
    let(:table_prefix) { 'custom_' }

    it 'uses the real helper fallback without treating NULL as indicator zero' do
      mod.run
      expect(credentials.first[:private_data]).to eq(hash_value)
      expect(queries.any? { |query| query.include?('from custom_users') }).to be(true)
    end

    context 'when the scalar is empty text' do
      let(:prefix_miss) { '' }

      it 'also falls back instead of matching indicator zero' do
        mod.run
        expect(queries.any? { |query| query.include?('from custom_users') }).to be(true)
      end
    end
  end

  context 'with a synthetic valid SQL NULL scalar' do
    let(:query_reply) { scalar(nil) }

    it('returns Safe rather than a missing-response error') { expect(mod.check.code).to eq('safe') }
  end

  context 'with a valid empty native result' do
    let(:query_reply) { response('empty') }

    it('returns reason-bearing Safe') { expect(mod.check).to have_attributes(code: 'safe', reason: a_string_matching(/SQL injection/)) }
    it('aborts a disabled-AutoCheck run') { rejected(Msf::Module::Failure::NotVulnerable) }
  end

  { 'nil' => nil, '401' => 401, '403' => 403, '404' => 404, '500' => 500 }.each do |label, status|
    context "with SQL request response #{label}" do
      let(:query_reply) { status == 401 ? response('denied') : status && reply(status, 'Error') }

      it('returns reason-bearing Unknown') { expect(mod.check).to have_attributes(code: 'unknown', reason: a_string_matching(/Depicter|SQL/)) }
      it 'aborts without report or loot' do
        reason = if status.nil?
                   Msf::Module::Failure::Unreachable
                 elsif [401, 403].include?(status)
                   Msf::Module::Failure::NoAccess
                 else
                   Msf::Module::Failure::UnexpectedReply
                 end
        rejected(reason)
      end
    end
  end

  # Mutation-derived schema cases, not additional captured vendor responses.
  ['not JSON', 'null', '[]', '{}', '{"hits":{}}', '{"hits":[null]}', '{"hits":[{"content":null}]}', '{"hits":[{"content":{}}]}', '{"hits":[{"content":{"id":[]}}]}', '{"hits":[{"content":{"id":true}}]}'].each do |body|
    context "with malformed SQL JSON #{body}" do
      let(:query_reply) { reply(200, body) }

      it('returns Unknown without raising') { expect(mod.check.code).to eq('unknown') }
    end
  end

  context 'with malformed JSON during disabled-AutoCheck collection' do
    let(:query_reply) { reply(200, '{"hits":[{"content":{}}]}') }

    it('aborts before credentials or loot') { rejected(Msf::Module::Failure::UnexpectedReply) }
  end

  [Rex::ConnectionRefused.new, Rex::TimeoutError.new, OpenSSL::SSL::SSLError.new('Unit TLS failure')].each do |error|
    context "with expected transport exception #{error.class}" do
      before { allow(mod).to receive(:send_request_cgi).and_raise(error) }

      it 'returns Unknown from check and Unreachable from run' do
        result = nil
        expect { result = mod.check }.not_to raise_error
        expect(result.code).to eq('unknown')
        rejected(Msf::Module::Failure::Unreachable)
      end
    end
  end

  context 'with an incomplete synthetic later row' do
    let(:incomplete_row) { true }

    before { mod.datastore['COUNT'] = 0 }

    it('fails before any credential persistence') { rejected(Msf::Module::Failure::UnexpectedReply) }
  end

  context 'with SQL NULL during a dump query' do
    let(:missing_dump_scalar) { true }

    it('fails instead of producing bogus empty loot') { rejected(Msf::Module::Failure::UnexpectedReply) }
  end

  # Synthetic decoder faults: Rex::Text.hex_to_raw otherwise accepts both.
  %w[ABC ZZZZ].each do |value|
    context "with malformed encoded later field #{value}" do
      let(:malformed_hex) { value }

      before { mod.datastore['COUNT'] = 0 }

      it('rejects before any persistence') { rejected(Msf::Module::Failure::UnexpectedReply) }
    end
  end

  context 'with a synthetic nonnumeric row count' do
    let(:invalid_row_count) { true }

    it('does not turn it into a successful empty dump') { rejected(Msf::Module::Failure::UnexpectedReply) }
  end

  it 'preserves options over repeated runs and uses the newly selected path' do
    mod.run
    profile['ajax'] = '/wordpress/wp-admin/admin-ajax.php'
    mod.datastore.merge!('TARGETURI' => '/wordpress/', 'COUNT' => 2)
    settings = mod.datastore.to_h.dup
    mod.run
    expect(credentials.length).to eq(3)
    expect(mod.datastore.to_h).to eq(settings)
  end

  it 'does not reuse successful state after selecting a missing installation' do
    expect(mod.check.code).to eq('vulnerable')
    mod.datastore['TARGETURI'] = '/module-target-missing/'
    rejected(Msf::Module::Failure::UnexpectedReply)
  end

  it 'preserves normal AutoCheck collection' do
    mod.datastore['AutoCheck'] = true
    mod.run
    expect(credentials.first[:private_data]).to eq(hash_value)
  end
end
