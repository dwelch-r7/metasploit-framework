require 'acceptance_spec_helper'
require 'digest'
require_relative '../../../test/module_targets/flowise/acceptance_helpers'
require_relative '../../../test/module_targets/flowise/native_session_calibration'

profile = ENV.fetch('FLOWISE_PROFILE', 'flowise_300')
profiles = JSON.parse(File.read('test/module_targets/flowise/profiles.json'))
raise ArgumentError, "Unknown Flowise profile: #{profile}" unless profiles.key?(profile)

RSpec.describe 'Native Flowise command, session and account targets' do
  include_context 'module target'
  include_context 'wait_for_expect'
  prepend FlowiseAcceptance
  include FlowiseNativeSessionCalibration

  before(:all) do
    @profile = profile
    output, error, status = Open3.capture3('python3', '-B', 'test/module_targets/flowise/native_probe.py')
    File.write(artifact('native-status.json'), JSON.pretty_generate(exitstatus: status.exitstatus, stderr: error))
    expect(status.success?).to be(true), error
    @native = JSON.parse(output)
    expect(@native.values_at('profile', 'version')).to eq([profile, profiles.fetch(profile).fetch('version')])
    target_runtime['module_endpoints'] = JSON.parse(File.read(artifact('native-endpoints.json'))).fetch('module_endpoints')
    calibrate_native_flowise_fetch if %w[flowise_300 flowise_305].include?(profile)
    calibrate_native_flowise_python if profile == 'flowise_311'
    selected = profiles.fetch(profile).fetch('modules')
    code = "load \"test/module_targets/flowise/input_audit.rb\";puts \"FLOWISE_CATALOG=\"+FlowiseInputs.install(framework,#{JSON.generate(selected)}).to_json"
    calibration = console_command("irb -e #{code.inspect}")
    catalog = JSON.parse(calibration[/^FLOWISE_CATALOG=(\{.*\})\r?$/, 1])
    expect(catalog.keys.sort).to eq(selected.sort)
    catalog.except(FlowiseInputs::ATO).each do |name, value|
      expect(value.fetch('generic_compatible')).to be(true)
      expect(value.fetch('target_name')).to eq(name == FlowiseInputs::MCP ? 'Unix Command' : 'Unix/Linux Command')
    end
    expect(catalog.fetch(FlowiseInputs::JS).fetch('fetch_compatible')).to be(true) if selected.include?(FlowiseInputs::JS)
    expect(catalog.fetch(FlowiseInputs::MCP).fetch('python_compatible')).to be(true) if selected.include?(FlowiseInputs::MCP)
    expect(rows).to eq([])
    if profiles.fetch(profile).fetch('database')
      connected = console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)
      expect(connected).not_to match(/\[-\]|Error|Exception/)
      expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
      File.write(artifact('reporting-schema.csv'), sql("SELECT table_name,column_name,data_type FROM information_schema.columns WHERE table_schema='public' ORDER BY table_name,ordinal_position"))
    end
  end

  before do |example|
    @case_id = example.metadata.fetch(:scoped_id).tr(':', '_')
    @case_input_offset = rows.length
    expect(console_command('sessions -l')).to include('No active sessions')
    expect(console_command('jobs -l')).to include('No active jobs')
    if profiles.fetch(profile).fetch('database')
      @workspace = "flowise_#{@case_id}"
      expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
      expect(service_rows).to eq([])
    end
  end

  if profile == 'flowise_300'
    it 'checks and executes customMCP quiet commands twice with exact restoration' do
      check(FlowiseInputs::CUSTOM, vulnerable: true)
      command_proof(FlowiseInputs::CUSTOM, quiet: true)
    end

    it 'checks and uses the JS fetch session twice with PID and file cleanup proof' do
      check(FlowiseInputs::JS, vulnerable: true)
      session_proof(FlowiseInputs::JS)
    end

    it 'refuses unrelated Apache and genuine missing paths twice for both owners' do
      [FlowiseInputs::CUSTOM, FlowiseInputs::JS].each do |owner|
        %w[unrelated missing].each do |service|
          2.times do
            output = invoke(owner, service: service, action: 'check', allow_errors: true)
            expect(output).not_to include('The target appears to be vulnerable', 'The target is vulnerable')
          end
          refused(owner, { 'AutoCheck' => false }, service: service)
        end
      end
    end
  elsif profile == 'flowise_basic'
    it 'uses real legacy Basic twice and refuses wrong or missing credentials for both owners' do
      [FlowiseInputs::CUSTOM, FlowiseInputs::JS].each do |owner|
        command_proof(owner)
        refused(owner, { 'FLOWISE_PASSWORD' => 'module-target-wrong-password' })
        refused(owner, { 'FLOWISE_USERNAME' => '', 'FLOWISE_PASSWORD' => '' })
      end
    end
  elsif profile == 'flowise_305'
    it 'uses JS with real JWT twice and refuses wrong or missing account credentials' do
      session_proof(FlowiseInputs::JS)
      refused(FlowiseInputs::JS, { 'FLOWISE_PASSWORD' => 'FlowiseWrong!42' })
      refused(FlowiseInputs::JS, { 'FLOWISE_EMAIL' => '', 'FLOWISE_PASSWORD' => '' })
    end

    it 'takes over an actual account twice with exact loot, fresh logins and legitimate recovery' do
      reset_account(affected: true)
    end

    it 'refuses a nonexistent victim twice without false credential loot' do
      2.times do |iteration|
        checkpoint(iteration) do
          output = invoke(FlowiseInputs::ATO, { 'EMAIL' => 'missing@module-target.test', 'NEWPASSWORD' => 'FlowiseChanged!42' }, allow_errors: true)
          expect(output).not_to include('Password reset successful')
          expect(loot_files).to eq(@before_loot)
          expect([200, 201]).to include(native(action: 'login').fetch('status'))
        end
      end
    end
  elsif profile == 'flowise_306'
    it 'checks fixed JS and enforces default blocking and real override refusal twice' do
      [FlowiseInputs::CUSTOM, FlowiseInputs::JS].each { |owner| check(owner, vulnerable: false) }
      refused(FlowiseInputs::JS)
      refused(FlowiseInputs::JS, { 'AutoCheck' => false })
      refused(FlowiseInputs::CUSTOM, { 'AutoCheck' => false })
    end

    it 'refuses reset-token disclosure twice while original login and email recovery work' do
      check(FlowiseInputs::ATO, vulnerable: false)
      reset_account(affected: false)
    end
  elsif profile == 'flowise_311'
    it 'uses npx tar delivery and command-shell sessions twice with exact service reporting' do
      check(FlowiseInputs::MCP, vulnerable: true)
      expect_service(version_info: true)
      session_proof(FlowiseInputs::MCP)
      expect_service
    end

    it 'refuses wrong or missing JWT twice without archive delivery or false access reporting' do
      ['FlowiseWrong!42', ''].each do |password|
        refused(FlowiseInputs::MCP, { 'PASSWORD' => password })
        expect(rows.drop(@case_input_offset).select { |row| row['kind'] == 'HTTP-REQUEST' }).to eq([])
        expect_service
      end
    end
  else
    it 'checks fixed npx and refuses default and explicit bypass twice with real reporting' do
      check(FlowiseInputs::MCP, vulnerable: false)
      expect_service(version_info: true)
      refused(FlowiseInputs::MCP)
      refused(FlowiseInputs::MCP, { 'AutoCheck' => false })
      expect(rows.drop(@case_input_offset).select { |row| row['kind'] == 'HTTP-REQUEST' }).to eq([])
      expect_service
    end
  end

  def reset_account(affected:)
    2.times do |iteration|
      checkpoint(iteration) do
        changed = "FlowiseChanged!#{iteration}a"
        expect([200, 201]).to include(native(action: 'login').fetch('status'))
        output = invoke(FlowiseInputs::ATO, { 'EMAIL' => FlowiseAcceptance::EMAIL, 'NEWPASSWORD' => changed }, allow_errors: !affected)
        if affected
          expect(output).to include('Password reset successful')
          fresh = loot_files - @before_loot
          expect(fresh.length).to eq(1)
          expect(JSON.parse(File.binread(fresh.fetch(0)))).to eq('email' => FlowiseAcceptance::EMAIL, 'password' => changed)
          expect([200, 201]).to include(native(action: 'login', password: changed).fetch('status'))
          expect([400, 401, 403, 404]).to include(native(action: 'login').fetch('status'))
          request = @last_inputs.find { |row| row['kind'] == 'REQUEST-ARGS/RESPONSE-BODY' && row['uri'].end_with?('/reset-password') }
          actual = JSON.parse(Base64.strict_decode64(request.fetch('data_base64')))
          expect(native(action: 'request', path: '/api/v1/account/reset-password', data: actual).fetch('status')).to eq(400)
        else
          expect(output).not_to include('Password reset successful')
          expect(loot_files).to eq(@before_loot)
          expect(@last_inputs.select { |row| row['kind'] == 'REQUEST-ARGS/RESPONSE-BODY' && row['method'] == 'POST' }).to eq([])
          forced = invoke(FlowiseInputs::ATO, { 'EMAIL' => FlowiseAcceptance::EMAIL, 'NEWPASSWORD' => changed, 'AutoCheck' => false }, allow_errors: true)
          expect(forced).to include('Could not retrieve password reset token')
          expect([200, 201]).to include(native(action: 'login').fetch('status'))
        end
      ensure
        expect(native(action: 'restore').fetch('login_accepted')).to be(true)
      end
    end
  end

  def sql(query)
    target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-Atc', query)
  end

  def service_rows
    query = "SELECT COALESCE(json_agg(row),'[]'::json) FROM (SELECT w.name workspace,h.address,s.id,s.port,s.proto,s.name,s.state,s.info FROM services s JOIN hosts h ON h.id=s.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}' ORDER BY s.id) row"
    JSON.parse(sql(query))
  end

  def expect_service(version_info: false)
    records = nil
    wait_target(15) do
      records = service_rows
      expect(records.length).to eq(1)
    end
    endpoint = target_runtime.fetch('module_endpoints').fetch('app')
    expect(records.fetch(0)).to include('workspace' => @workspace, 'address' => endpoint.fetch('host'), 'port' => 3000, 'proto' => 'tcp', 'name' => 'http', 'state' => 'open')
    expect(records.fetch(0).fetch('info')).to eq("Flowise #{@native.fetch('version')}") if version_info
    record('service-reporting.jsonl', workspace: @workspace, rows: records)
  end
end
