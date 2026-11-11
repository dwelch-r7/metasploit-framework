require 'acceptance_spec_helper'
require_relative '../../../test/module_targets/minio/acceptance'

# Normal discovery loads excluded acceptance files without campaign runtime.
runtime_path = ENV['MODULE_TARGET_RUNTIME']
profile = runtime_path ? JSON.parse(File.read(runtime_path)).fetch('profile') : 'vulnerable'
raise ArgumentError, 'Unknown MinIO profile' unless %w[vulnerable fixed].include?(profile)

RSpec.describe 'Genuine MinIO owners and credential evidence' do
  include_context 'MinIO owner evidence'

  before(:all) do
    native = JSON.parse(File.read(target_runtime.fetch('native_before')))
    expect(native.fetch('facts')).to include('restored' => true, 'cleanup_errors' => [])
    expect(minio_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
    identity = minio_sql('SELECT current_user,current_database(),version()')
    expect(identity).to start_with('module_framework|module_targets|PostgreSQL 16.')
    connected = console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)
    expect(connected).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    expect(minio_sql('SELECT count(*) FROM metasploit_credential_cores').strip).to eq('0')
    schema = minio_sql("SELECT table_name,column_name,data_type FROM information_schema.columns WHERE table_schema='public' ORDER BY table_name,ordinal_position")
    versions = console_command(%q{irb -e 'puts JSON.generate(Gem.loaded_specs.slice("metasploit-credential","metasploit-model","metasploit_data_models","metasploit-payloads","metasploit_payloads-mettle").transform_values { |spec| {version:spec.version.to_s,path:spec.full_gem_path} })'})
    File.write(File.join(target_runtime.fetch('artifacts'), 'actual-framework-database.txt'), identity + schema + versions)
    expect(versions).to include('6.0.26', '5.0.6')
  end

  before do |example|
    @workspace = "minio_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    @invocation = 0
    @session_launch_attempted = false
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(minio_rows).to eq([])
    expect(minio_loots).to eq([])
  end

  after do
    errors = []
    if @session_launch_attempted
      begin
        console_command("sessions -k #{@session_id}") if @session_id
        console_command('jobs -K')
      rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
        errors << { operation: 'session-close', error: "#{e.class}: #{e.message}" }
      end
      begin
        host_control('session_fixture.py', @workspace, 'cleanup', @session_kind)
      rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
        errors << { operation: 'session-process-cleanup', error: "#{e.class}: #{e.message}" }
      end
    end
    evidence('cleanup', errors) if @workspace
    expect(errors).to eq([])
  end

  if profile == 'vulnerable'
    %w[node1 node2].each do |service|
      it "captures genuine #{service} disclosure, JSON loot, Untried SQL and derived S3 twice" do
        first = bootstrap(service, s3_proof: true)
        expect(bootstrap(service, s3_proof: true)).to eq(first)
      end
    end

    it 'keeps identical disclosed credentials isolated and repeatable in two fresh workspaces' do
      original = @workspace
      first = bootstrap('node1', s3_proof: false)
      expect(bootstrap('node1', s3_proof: false)).to eq(first)
      @workspace += '_other'
      expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
      expect(minio_rows).to eq([])
      expect(minio_loots).to eq([])
      other = bootstrap('node1', s3_proof: false)
      expect(bootstrap('node1', s3_proof: false)).to eq(other)
      %w[core_id login_id origin_id host_id service_id credential_workspace_id host_workspace_id].each do |key|
        expect(first.fetch(0).fetch(key)).not_to eq(other.fetch(0).fetch(key))
      end
      expect(minio_rows(original)).to eq(first)
    end
  else
    %w[node1 node2].each do |service|
      it "rejects actual fixed #{service} disclosure twice without credentials or loot" do
        2.times { bootstrap(service, negative: true) }
      end
    end
  end

  it 'does not report either genuine node through a wrong TARGETURI' do
    %w[node1 node2].each { |service| bootstrap(service, negative: true, wrong_path: true) }
  end

  if profile == 'vulnerable'
    MinioTarget::Functional::CLIENT_KINDS.each do |kind|
      it "collects all seven client states through one genuine Linux #{kind} with input restoration" do
        open_minio_session(kind)
        MinioTarget::Functional::CLIENT_CASES.each do |name|
          with_minio_client_state(name) do |configs|
            if %w[missing empty malformed aliases_empty].include?(name)
              output = collect_client('')
              expect(output).to include('Configuration file not found:') if name == 'missing'
              expect(output).to include('Configuration file content is empty') if name == 'empty'
              expect(output).to include('Unable to parse configuration:') if name == 'malformed'
              expect(output).not_to include('MinIO Client Key', 'Session info stored in:')
              fixture('verify', name)
            elsif name == 'custom_path'
              2.times do
                output = collect_client(configs.fetch('custom').fetch('path'), expected_aliases: configs.fetch('custom').fetch('aliases'))
                expect(output).not_to include('module-home-secret-')
                fixture('verify', name)
              end
            else
              if name == 'default_after_custom'
                collect_client(configs.fetch('custom').fetch('path'), expected_aliases: configs.fetch('custom').fetch('aliases'))
                fixture('verify', name)
              end
              2.times do
                output = collect_client('', expected_aliases: configs.fetch('home').fetch('aliases'))
                expect(output).not_to include('module-custom-secret-')
                fixture('verify', name)
              end
            end
          end
        end
      end
    end
  end
end
