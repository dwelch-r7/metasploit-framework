require 'acceptance_spec_helper'
require_relative '../../../../test/module_targets/4gaboards/acceptance'

profile = ENV.fetch('BOARDS_PROFILE', 'vulnerable')

RSpec.describe 'Genuine 4gaBoards user information collection', acceptance: true do
  include_context 'module target'
  include Acceptance::FourgaBoards

  before(:all) do
    @app = profile != 'unrelated'
    @fixed = profile == 'fixed'
    @native = boards_native('before')
    expect(boards_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
    connected = console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)
    expect(connected).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    host = target_runtime.fetch('module_endpoints').fetch('target').fetch('host')
    proof = console_command("irb -e 'begin; Socket.tcp(#{host.inspect}, 1, connect_timeout: 2).close; puts \"BOARDS_REFUSED=false\"; rescue Errno::ECONNREFUSED; puts \"BOARDS_REFUSED=true\"; end'")
    expect(proof).to include('BOARDS_REFUSED=true')
  end

  after(:all) do
    if @native
      current = boards_native('after')
      keys = @app ? %w[files identity schema_count core ordinary_sha256] : %w[identity ordinary_sha256]
      keys.each { |key| expect(current.fetch(key)).to eq(@native.fetch(key)) }
      if @app
        fields = %w[id email name username isAdmin phone organization ssoGithubEmail]
        expect(current.fetch('administrator').slice(*fields)).to eq(@native.fetch('administrator').slice(*fields))
        expect(current.fetch('expected_users').map { |row| row.fetch('id') }.sort).to eq(@native.fetch('expected_users').map { |row| row.fetch('id') }.sort)
      end
    end
  end

  before do |example|
    @workspace = "boards_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(boards_reports.values).to all(eq([]))
    @email = @workspace + '@module-target.invalid'
  end

  after { boards_reports if @workspace }

  if %w[vulnerable fixed].include?(profile)
    it 'collects exact disclosed or public profile fields twice and verifies administrator cleanup' do
      original = nil
      2.times do |index|
        rows = boards_harvest(@workspace + "_#{index}@module-target.invalid")
        stable = rows.slice('services', 'vulnerabilities')
        expect(stable).to eq(original) if original
        original = stable
      end
      expect(boards_reports.fetch('loot').length).to eq(2)
    end

    it 'accepts the administrator email for account cleanup' do
      boards_harvest(@email, 'ADMIN_USERNAME' => 'administrator@module-target.invalid')
    end

    {
      'no administrator credentials' => { 'ADMIN_USERNAME' => '', 'ADMIN_PASSWORD' => '' },
      'only an administrator username' => { 'ADMIN_PASSWORD' => '' },
      'only an administrator password' => { 'ADMIN_USERNAME' => '' }
    }.each do |label, options|
      it "retains collection and accurately warns with #{label}" do
        boards_harvest(@email, options, cleanup: false)
      end
    end

    it 'retains collected loot and identifies a rejected administrator login' do
      boards_harvest(@email, { 'ADMIN_PASSWORD' => 'module-target-rejected-password' }, cleanup: false, login_failure: true)
    end

    it 'rejects an existing email without reporting a vulnerability or removing the original account' do
      previous = boards_users
      2.times do
        output, paths = boards_call('native-reader@module-target.invalid')
        expect(output).to include('Email already in use. Supply a different email')
        expect(paths).to eq([])
        expect(boards_reports.values).to all(eq([]))
        expect(boards_users).to eq(previous)
      end
    end

    it 'finds the normalized newly registered account for a mixed-case email and deletes it' do
      boards_harvest(@email.upcase)
    end

    it 'rejects an invalid registration email without storing loot or reports' do
      output, paths = boards_call('not-an-email')
      expect(output).to include('Failed to register user')
      expect(paths).to eq([])
      expect(boards_reports.values).to all(eq([]))
    end
  else
    it 'refuses collection on the native-proven locked or unrelated application twice' do
      2.times do
        output, paths = boards_call(@email)
        expect(output).to include('Failed to register user')
        expect(paths).to eq([])
        expect(boards_reports.values).to all(eq([]))
      end
    end
  end

  it 'does not report a vulnerability, service or loot for a missing application path' do
    output, paths = boards_call(@email, 'TARGETURI' => '/module-target-missing')
    expect(output).to include('Failed to register user')
    expect(paths).to eq([])
    expect(boards_reports.values).to all(eq([]))
  end

  it 'does not report a vulnerability, service or loot for the native-proven refused port twice' do
    2.times do
      output, paths = boards_call(@email, 'RPORT' => 1)
      expect(output).to include('Failed to register user')
      expect(paths).to eq([])
      expect(boards_reports.values).to all(eq([]))
    end
  end
end
