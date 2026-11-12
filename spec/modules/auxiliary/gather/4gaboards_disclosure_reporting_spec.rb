require 'rspec'
require 'faker'
require 'msfenv'
require 'msf/base'

RSpec.describe '4gaBoards disclosure reporting contracts' do
  let(:fixture_path) { File.expand_path('../../../file_fixtures/modules/auxiliary/4gaboards_disclosure', __dir__) }
  let(:version) { '3.3.8' }
  let(:body) { File.binread(File.join(fixture_path, "native-#{version}-reader-users.json")) }
  let(:requests) { [] }
  let(:loot) { [] }
  let(:services) { [] }
  let(:vulnerabilities) { [] }
  let(:messages) { [] }
  let(:admin_status) { 200 }
  let(:mod) { @framework.modules.create('auxiliary/gather/4gaboards_users_info_disclosure_cve_2026_53959') }

  before(:context) do
    @framework = Msf::Simple::Framework.create('DisableDatabase' => true, 'DeferModuleLoads' => true)
    path = ENV.fetch('FOURGA_UNIT_MODULE_ROOT', File.expand_path('../../../../modules', __dir__))
    loader = @framework.modules.send(:loaders).find { |candidate| candidate.loadable?(path) }
    raise 'Could not load 4gaBoards module' unless loader.load_module(path, 'auxiliary', 'gather/4gaboards_users_info_disclosure_cve_2026_53959')
  end

  after(:context) do
    @framework.threads.each { |thread| thread.kill if thread&.alive? }
  end

  before do
    mod.datastore['RHOSTS'] = '192.0.2.1'
    mod.datastore['EMAIL'] = 'native-reader@module-target.invalid'
    mod.datastore['ADMIN_USERNAME'] = 'unit-admin'
    mod.datastore['ADMIN_PASSWORD'] = 'unit-admin-password'
    allow(Faker::Internet).to receive(:password).and_return('Unit-only-password!2026')
    %i[print_status print_good print_warning vprint_status].each do |method|
      allow(mod).to receive(method) { |message| messages << message }
    end
    allow(mod).to receive(:report_service) { |data| services << data }
    allow(mod).to receive(:report_vuln) { |data| vulnerabilities << data }
    allow(mod).to receive(:store_loot) do |*data|
      loot << data
      '/unit/4gaboards-users.json'
    end
    # Native GET/users bytes use the real response parser. Other HTTP exchanges
    # are deterministic doubles; no target, authentication or SQL is exercised.
    allow(mod).to receive(:send_request_cgi) do |data|
      requests << data
      case data.fetch('uri')
      when %r{/api/register\z}
        response(200, '{"item":"unit-registration-token"}')
      when %r{/api/access-tokens\z}
        response(admin_status, admin_status == 200 ? '{"item":"unit-admin-token"}' : '{"message":"Invalid credentials"}')
      when %r{/api/users\z}
        response(200, body)
      when %r{/api/users/\d+\z}
        response(200, JSON.generate('item' => { 'id' => data.fetch('uri').split('/').last }))
      else
        raise ArgumentError, "Unexpected unit request: #{data.inspect}"
      end
    end
  end

  it 'reports private fields from another user in the native response' do
    mod.run

    expect(vulnerabilities).to include(include(host: '192.0.2.1', port: 3000, proto: 'tcp', name: mod.fullname))
  end

  it 'stores all native other-user fields without retaining the newly registered profile' do
    mod.run

    expect(JSON.parse(loot.fetch(0).fetch(3))).to eq(JSON.parse(body).fetch('items').reject { |user| user['email'] == mod.datastore['EMAIL'] })
  end

  it 'retains the existing HTTP service reporting arguments' do
    mod.run

    expect(services).to eq([{ host: '192.0.2.1', port: 3000, proto: 'tcp', name: 'http' }])
  end

  it 'uses the native self identifier for administrator cleanup' do
    mod.run

    expect(requests.last.slice('uri', 'method', 'headers')).to eq({
      'uri' => '/api/users/' + self_identifier, 'method' => 'DELETE', 'headers' => { 'Authorization' => 'Bearer unit-admin-token' }
    })
  end

  it 'retains target subpath handling through the actual URI builder' do
    mod.datastore['TARGETURI'] = '/boards/'
    mod.run

    expect(requests.map { |data| data.fetch('uri') }).to eq(['/boards/api/register', '/boards/api/users', '/boards/api/access-tokens', '/boards/api/users/' + self_identifier])
  end

  context 'native fixed user list' do
    let(:version) { '3.3.9' }

    it 'does not report the requesting account own private profile as a disclosure' do
      mod.run

      expect(vulnerabilities).to eq([])
    end

    it 'preserves the collected public profile as JSON loot' do
      mod.run

      expect(JSON.parse(loot.fetch(0).fetch(3))).to eq(JSON.parse(body).fetch('items').reject { |user| user['email'] == mod.datastore['EMAIL'] })
    end

    it 'still reports the service and completes administrator cleanup' do
      mod.run

      expect([services.length, requests.last.fetch('method'), requests.last.fetch('uri')]).to eq([1, 'DELETE', '/api/users/' + self_identifier])
    end

    it 'retains the no-administrator warning without a vulnerability report' do
      mod.datastore['ADMIN_USERNAME'] = ''
      mod.datastore['ADMIN_PASSWORD'] = ''
      mod.run

      expect([vulnerabilities, requests.length, messages.include?('Administrator credentials not provided')]).to eq([[], 2, true])
    end

    context 'rejected administrator authentication' do
      let(:admin_status) { 401 }

      it 'keeps public loot and fails cleanup without inventing a disclosure' do
        expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, /Failed to login as administrator/)

        expect([loot.length, vulnerabilities, requests.map { |data| data.fetch('method', 'GET') }]).to eq([1, [], %w[POST GET POST]])
      end
    end

    it 'reevaluates returned data when a later run has only public fields' do
      first = response(200, File.binread(File.join(fixture_path, 'native-3.3.8-reader-users.json')))
      allow(mod).to receive(:send_request_cgi).with(hash_including('method' => 'GET', 'uri' => '/api/users')).and_return(first, response(200, body))
      mod.run
      mod.run

      expect(vulnerabilities.length).to eq(1)
    end
  end

  context 'synthetic partial profile responses' do
    let(:version) { '3.3.9' }

    it 'does not report an empty other-user list' do
      replace_other_user(nil)
      mod.run

      expect([JSON.parse(loot.fetch(0).fetch(3)), vulnerabilities]).to eq([[], []])
    end

    it 'does not infer a vulnerability from an unknown public field' do
      replace_other_user(other_user.merge('displayColor' => 'blue'))
      mod.run

      expect(vulnerabilities).to eq([])
    end

    it 'does not report empty private fields as disclosed values' do
      replace_other_user(other_user.merge('email' => '', 'phone' => nil, 'organization' => nil, 'isAdmin' => nil))
      mod.run

      expect(vulnerabilities).to eq([])
    end

    it 'recognizes false as a disclosed private administrator flag' do
      replace_other_user(other_user.merge('isAdmin' => false))
      mod.run

      expect(vulnerabilities.length).to eq(1)
    end

    it 'recognizes a disclosed SSO email without requiring the normal email field' do
      replace_other_user(other_user.merge('ssoGithubEmail' => 'fixture-github@module-target.invalid'))
      mod.run

      expect(vulnerabilities.length).to eq(1)
    end
  end

  def response(code, body)
    result = Rex::Proto::Http::Response.new
    result.code = code
    result.body = body
    result
  end

  def self_identifier
    JSON.parse(body).fetch('items').find { |user| user['email'] == mod.datastore['EMAIL'] }.fetch('id')
  end

  def other_user
    JSON.parse(body).fetch('items').find { |user| user['email'] != mod.datastore['EMAIL'] }
  end

  def replace_other_user(value)
    users = JSON.parse(body).fetch('items').select { |user| user['email'] == mod.datastore['EMAIL'] }
    users.unshift(value) if value
    allow(mod).to receive(:send_request_cgi).with(hash_including('method' => 'GET', 'uri' => '/api/users')).and_return(response(200, JSON.generate('items' => users)))
  end
end
