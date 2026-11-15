require 'rspec'
require 'msfenv'
require 'msf/base'

RSpec.describe 'Piwigo credential reporting contracts' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('PIWIGO_OWNER_SOURCE', File.expand_path('../../../../modules/auxiliary/gather/piwigo_cve_2023_26876.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:captures) { JSON.parse(File.read(File.expand_path('../../../file_fixtures/modules/auxiliary/gather/piwigo_cve_2023_26876/responses.json', __dir__))).fetch('responses') }
  # Inert synthetic phpass-format value, not a native credential.
  let(:hash_value) { '$P$B12345678abcdefghijklmnopqrstuv' }
  let(:rows) { [['module_admin', hash_value], ['guest', nil]] }
  let(:credentials) { [] }
  let(:requests) { [] }
  let(:queries) { [] }
  let(:lines) { [] }
  let(:version) { '13.5.0' }
  let(:home) { response('populated_home', version: version) }
  let(:identification) { response('identification', version: version) }
  let(:login_reply) { response('login_success') }
  let(:history_code) { 200 }
  let(:history_missing) { false }
  let(:bad_extraction) { false }
  let(:empty_probe) { false }
  let(:require_login_cookie) { false }
  let(:login_cookie_snapshots) { [] }
  let(:framework) { double('Framework', datastore: Msf::DataStore.new) }

  before do
    mod.datastore.merge!('RHOSTS' => '192.0.2.10', 'RHOST' => '192.0.2.10', 'RPORT' => 80, 'SSL' => false, 'TARGETURI' => '/', 'USERNAME' => 'module_admin', 'PASSWORD' => 'unit-password', 'AutoCheck' => false)
    allow(mod).to receive(:framework).and_return(framework)
    allow(mod).to receive(:user_output).and_return(Rex::Ui::Text::Output::Buffer.new)
    allow(mod).to receive(:myworkspace_id).and_return(1)
    allow(mod).to receive(:create_credential) { |data| credentials << data }
    allow(mod).to receive(:print_line) { |text| lines << text }
    %i[print_good print_status print_error print_warning vprint_status vprint_error elog].each { |method| allow(mod).to receive(method) }
    # HTTP/reporting/UI are doubles; actual SQLi Common query generation,
    # HEX decoding, safe extraction, hash identification and AutoCheck run.
    # This bounded SQL adapter models query families, not a native database.
    allow(mod).to receive(:send_request_cgi) do |options|
      requests << options
      if options['method'] == 'POST'
        # Native identification.php47-53 rejects a POST without its session cookie.
        if require_login_cookie && mod.cookie_jar.empty?
          reply(200, 'Cookies are blocked or not supported by your browser.')
        else
          login_reply
        end
      elsif options.fetch('uri').end_with?('index.php')
        home
      elsif options.fetch('uri').end_with?('identification.php')
        login_cookie_snapshots << mod.cookie_jar.cookies.map(&:name)
        mod.cookie_jar.parse_and_merge('pwg_id=unit-session; Path=/', 'http://192.0.2.10/')
        identification
      else
        history_response(options)
      end
    end
  end

  def response(name, version: '13.5.0')
    capture = captures.fetch(name)
    reply(capture.fetch('code'), capture.fetch('body').gsub('13.5.0', version), capture.fetch('headers'))
  end

  def reply(code, body = '', headers = {})
    Rex::Proto::Http::Response.new(code).tap do |result|
      result.body = body
      headers.each { |name, value| result.headers[name] = value }
    end
  end

  def scalar_response(value)
    reply(history_code, captures.fetch('scalar').fetch('body').sub('UNIT_SCALAR', value))
  end

  def history_response(options)
    return nil if history_missing
    return reply(history_code) unless history_code == 200

    sql = options.fetch('vars_get').fetch('filter_user_id').delete_prefix('123123123 union all ')
    queries << sql
    return reply(200, '<html>Query rejected</html>') if empty_probe
    return reply(200, '<html>Missing result</html>') if bad_extraction && sql.include?('count(1)')

    if (match = sql.match(/\Aselect hex\(0x([0-9a-f]+)\)\z/i))
      scalar_response(match[1].upcase)
    elsif sql == 'select 0x70776e3364'
      scalar_response('pwn3d')
    elsif sql == 'select count(1) from piwigo_users'
      scalar_response(rows.length.to_s)
    elsif (match = sql.match(/from piwigo_users limit (\d+),1\z/))
      row = rows.fetch(match[1].to_i)
      scalar_response(row.map { |field| field.to_s.b.unpack1('H*').upcase }.join(';'))
    elsif sql.include?('group_concat')
      # Parent native controls independently demonstrated this96-byte limit.
      scalar_response(rows.map { |user, hash| [user, hash].join(';') }.join(',').b.byteslice(0, 96))
    else
      raise ArgumentError, "Unexpected unit SQL query: #{sql}"
    end
  end

  def rejected(reason)
    expect { mod.run }.to raise_error(Msf::Auxiliary::Failed)
    expect(mod.fail_reason).to eq(reason)
    expect(credentials).to be_empty
  end

  it 'persists the extracted hash rather than the username' do
    mod.run
    expect(credentials).to contain_exactly(hash_including(username: 'module_admin', private_data: hash_value, private_type: :nonreplayable_hash, jtr_format: 'phpass'))
  end

  it 'displays the NULL guest without inventing a private hash' do
    mod.run
    expect(lines.join).to include('guest')
    expect(credentials.map { |data| data.fetch(:username) }).to eq(['module_admin'])
  end

  context 'with the native cookie-before-POST requirement' do
    let(:require_login_cookie) { true }

    it 'initializes login independently of AutoCheck' do
      mod.run
      expect(requests.first(2).map { |options| [options['method'], options['uri'], options['keep_cookies']] }).to eq([['GET', '/identification.php', true], ['POST', '/identification.php', true]])
      expect(credentials.map { |data| data.fetch(:private_data) }).to eq([hash_value])
    end
  end

  it 'does not reuse an authenticated cookie when credentials change' do
    mod.cookie_jar.parse_and_merge('pwg_id=old-authenticated-session; Path=/', 'http://192.0.2.10/')
    mod.run
    mod.datastore.merge!('USERNAME' => 'other-user', 'PASSWORD' => 'other-password')
    mod.run
    expect(login_cookie_snapshots).to eq([[], []])
    expect(requests.select { |options| options['method'] == 'POST' }.map { |options| options.fetch('vars_post').fetch('username') }).to eq(['module_admin', 'other-user'])
  end

  context 'with delimiter and Unicode usernames' do
    let(:rows) { [['owned,comma;semi', hash_value], ['owned_é雪', hash_value], ['guest', nil]] }

    it 'keeps each username/hash pair intact and UTF-8 compatible' do
      mod.run
      expect(credentials.map { |data| [data.fetch(:username), data.fetch(:private_data)] }).to eq(rows.first(2))
      expect(credentials.all? { |data| data.fetch(:username).encoding == Encoding::UTF_8 }).to be(true)
    end
  end

  context 'with a collection exceeding GROUP_CONCAT capacity' do
    let(:rows) { Array.new(24) { |index| ["owned_#{index}", hash_value] } }

    it 'retrieves every row through actual safe Common queries' do
      mod.run
      expect(credentials.map { |data| data.fetch(:private_data) }).to eq(Array.new(24, hash_value))
      expect(queries.none? { |query| query.include?('group_concat') }).to be(true)
      expect(queries.count { |query| query.match?(/limit \d+,1\z/) }).to eq(24)
    end
  end

  context 'with an empty rather than NULL hash' do
    let(:rows) { [['empty', ''], ['module_admin', hash_value]] }

    it 'does not create an empty nonreplayable hash' do
      mod.run
      expect(credentials.map { |data| data.fetch(:username) }).to eq(['module_admin'])
    end
  end

  context 'with only one user' do
    let(:rows) { [['module_admin', hash_value]] }

    it 'prints the result table' do
      mod.run
      expect(lines.join).to include('Piwigo Users', 'module_admin')
    end
  end

  it 'permits repeated collection and preserves operator configuration' do
    settings = mod.datastore.to_h.dup
    2.times { mod.run }
    expect(credentials.map { |data| data.fetch(:private_data) }).to eq([hash_value, hash_value])
    expect(mod.datastore.to_h).to eq(settings)
  end

  ['/gallery/', '/gallery/index.php', '/gallery/identification.php'].each do |path|
    it "uses a consistent base path for #{path}" do
      mod.datastore['TARGETURI'] = path
      mod.run
      expect(requests.map { |options| options.fetch('uri') }.uniq).to eq(['/gallery/identification.php', '/gallery/admin.php'])
    end
  end

  { '13.1.0' => 'safe', '13.2.0' => 'appears', '13.4.0' => 'appears', '13.5.0' => 'appears', '13.6.0' => 'appears', '13.7.0' => 'safe', '14.0.0' => 'safe' }.each do |tag, expected|
    context "with synthetic version #{tag}" do
      let(:version) { tag }

      it('returns the source-supported result') { expect(mod.check.code).to eq(expected) }
    end
  end

  context 'with an empty gallery' do
    let(:home) { response('empty_home') }

    it 'uses the genuine identification-page version fallback' do
      expect(mod.check.code).to eq('appears')
      expect(requests.map { |options| options.fetch('uri') }).to eq(['/index.php', '/identification.php'])
    end
  end

  context 'with unrelated successful HTML' do
    let(:home) { reply(200, '<html>Unrelated</html>') }
    let(:identification) { home }

    it('returns reason-bearing Safe') { expect(mod.check).to have_attributes(code: 'safe', reason: 'Target did not identify as Piwigo') }
  end

  context 'with an unanswered version request' do
    let(:home) { nil }

    it('returns Unknown') { expect(mod.check.code).to eq('unknown') }
  end

  context 'with a missing version path' do
    let(:home) { reply(404) }

    it('returns Unknown') { expect(mod.check.code).to eq('unknown') }
  end

  context 'with rejected login' do
    let(:login_reply) { response('login_failure') }

    it 'returns NoAccess without SQL' do
      rejected(Msf::Module::Failure::NoAccess)
      expect(queries).to be_empty
    end
  end

  context 'with unanswered login' do
    let(:login_reply) { nil }

    it('returns Unreachable') { rejected(Msf::Module::Failure::Unreachable) }
  end

  context 'with denied history access' do
    let(:history_code) { 403 }

    it('returns NoAccess') { rejected(Msf::Module::Failure::NoAccess) }
  end

  context 'with unanswered history' do
    let(:history_missing) { true }

    it('returns Unreachable') { rejected(Msf::Module::Failure::Unreachable) }
  end

  context 'when the probe is rejected' do
    let(:empty_probe) { true }

    it('returns NotVulnerable') { rejected(Msf::Module::Failure::NotVulnerable) }
  end

  context 'when extraction loses its result after a successful probe' do
    let(:bad_extraction) { true }

    it('returns UnexpectedReply') { rejected(Msf::Module::Failure::UnexpectedReply) }
  end
end
