require 'acceptance_spec_helper'
require 'rbconfig'

RSpec.describe 'Genuine nested Docker Engine information' do
  include_context 'module target'

  before(:all) do
    argv = [RbConfig.ruby, 'test/module_targets/docker_engine/native_probe.rb']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-docker-engine.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-docker-engine-status.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    expect(stderr).to eq('')
    @native = JSON.parse(stdout).fetch('engines')
    output = console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)
    expect(output).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-reporting-schema.txt'), sql("SELECT table_name, column_name, data_type FROM information_schema.columns WHERE table_schema='public' ORDER BY table_name, ordinal_position"))
  end

  before do |example|
    @workspace = "docker_engine_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(notes).to eq([])
    expect(hosts).to eq([])
  end

  %w[old modern].each do |service|
    [false, true].each do |verbose|
      it "persists actual #{service} engine information twice with VERBOSE=#{verbose}" do
        verify_information(service, service, 'VERBOSE' => verbose)
      end
    end
  end

  it 'persists actual engine information twice through a Basic-authenticated gateway' do
    verify_information('gateway', 'modern', 'HttpUsername' => 'module-test-user', 'HttpPassword' => 'module-test-password')
  end

  it 'persists actual engine information twice through the real TLS gateway' do
    verify_information('gateway', 'modern', 'SSL' => true, 'RPORT' => 443)
  end

  [
    ['gateway', {}, 'absent gateway credentials'],
    ['gateway', { 'HttpUsername' => 'module-test-user', 'HttpPassword' => 'wrong-password' }, 'rejected gateway credentials'],
    ['unrelated', {}, 'unrelated Apache HTML with HTTP 200'],
    ['missing', {}, 'unrelated Apache HTTP 404']
  ].each do |service, options, label|
    it "refuses #{label} without storing host or version records" do
      output = gather(service, options, allow_errors: true)
      aggregate_failures do
        expect(output).not_to include('[Docker Server] Version:', 'Saving host information.')
        expect(notes).to eq([])
        expect(hosts).to eq([])
      end
    end
  end

  def verify_information(service, profile, options = {})
    expected = @native.fetch(profile)
    endpoint = target_runtime.fetch('module_endpoints').fetch(service)
    original = nil
    2.times do
      output = gather(service, options)
      expect(output).to include("[Docker Server] Version: #{expected.fetch('Version')}", 'Saving host information.')
      verbose = options.fetch('VERBOSE', true)
      expect(output.include?('All info:')).to eq(verbose)
      %w[Version ApiVersion GitCommit Os Arch KernelVersion].each { |field| expect(output).to include(expected.fetch(field)) } if verbose
      rows = notes
      expect(rows.size).to eq(1)
      # Match Note's Base64Serializer without deserializing database bytes.
      expect(rows.first).to include(
        'workspace' => @workspace, 'address' => endpoint.fetch('host'),
        'port' => options.fetch('RPORT', endpoint.fetch('port')), 'proto' => 'tcp', 'ntype' => 'docker_version',
        'data' => [Marshal.dump(version: expected.fetch('Version'))].pack('m')
      )
      expect(rows).to eq(original) if original
      original = rows
      expect(hosts).to eq([
        {
          # Mdm::Host retains an unlisted vendor spelling in detected_arch.
          'address' => endpoint.fetch('host'), 'arch' => 'Unknown',
          'detected_arch' => expected.fetch('Arch'), 'os_family' => expected.fetch('Os'),
          'info' => "Docker Server v.#{expected.fetch('Version')} Kernel Version: #{expected.fetch('KernelVersion')}"
        }
      ])
    end
  end

  def gather(service, options = {}, allow_errors: false)
    run_target_module('auxiliary/scanner/http/docker_version', service, { 'SSL' => false }.merge(options), allow_errors: allow_errors)
  end

  def notes
    query = <<~SQL
      SELECT COALESCE(json_agg(row), '[]') FROM (
        SELECT n.id, w.name AS workspace, host(h.address) AS address, s.port, s.proto, n.ntype, n.data
        FROM notes n JOIN workspaces w ON w.id=n.workspace_id
        JOIN hosts h ON h.id=n.host_id JOIN services s ON s.id=n.service_id
        WHERE w.name='#{@workspace}' ORDER BY n.id
      ) row
    SQL
    JSON.parse(sql(query))
  end

  def hosts
    query = <<~SQL
      SELECT COALESCE(json_agg(row), '[]') FROM (
        SELECT host(h.address) AS address, h.arch, h.detected_arch, h.os_family, h.info
        FROM hosts h JOIN workspaces w ON w.id=h.workspace_id
        WHERE w.name='#{@workspace}' ORDER BY h.id
      ) row
    SQL
    JSON.parse(sql(query))
  end

  def sql(query)
    target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
  end
end
