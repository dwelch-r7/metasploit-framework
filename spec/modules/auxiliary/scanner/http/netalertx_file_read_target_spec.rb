require 'acceptance_spec_helper'

RSpec.describe 'Genuine NetAlertX file collection', acceptance: true, order: :defined do
  include_context 'module target'

  before(:all) do
    @native = native_control('before')
    expect(sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
    expect(console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
  end

  before do |example|
    @workspace = "netalertx_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(reports).to eq('loot' => [], 'vulns' => [])
  end

  after do
    %w[sessions jobs].each do |kind|
      output = console_command("irb -e 'puts \"NETALERTX_CLEAN=\" + framework.#{kind}.keys.to_json'")
      expect(output).to include('NETALERTX_CLEAN=[]')
    end
  end

  after(:all) do
    if @native
      current = native_control('after')
      %w[version protected exposed bootstrap source_hashes database].each do |key|
        expect(current.fetch(key)).to eq(@native.fetch(key))
      end
    end
    %w[target framework reporting_db].each do |role|
      expect(target_exec(role, 'cat', '/sys/fs/cgroup/memory.events')).to include("oom 0\n", "oom_kill 0\n")
      expect(target_exec(role, 'cat', '/sys/fs/cgroup/pids.events').strip).to eq('max 0')
    end
  end

  it 'checks the real anonymous maintenance response twice' do
    2.times do
      output = owner({}, action: 'check')
      if protected?
        expect(output).to include('No response or unexpected status code from target')
      else
        expect(output).to include(version == '24.9.12' ? 'Version 24.9.12 detected.' : 'Version 24.10.12 detected, which is not vulnerable.')
      end
      data = reports
      expect(data.fetch('loot')).to eq([])
      if !protected? && version == '24.9.12'
        expect(data.fetch('vulns').length).to eq(1)
        row = data.fetch('vulns').first
        expect(row.fetch('name').strip).to eq('NetAlertX File Read Vulnerability')
        expect(row.fetch('info')).to eq('Target appears vulnerable based on check of auxiliary/scanner/http/netalertx_file_read.')
      else
        expect(data.fetch('vulns')).to eq([])
      end
    end
  end

  it 'honors the default AutoCheck decision twice' do
    collect_twice({}, exposed: version == '24.9.12' && !protected?)
  end

  it 'collects or refuses a forced request twice using actual endpoint protection' do
    collect_twice({ 'ForceExploit' => true })
  end

  it 'collects or refuses with AutoCheck disabled twice' do
    collect_twice({ 'AutoCheck' => false })
  end

  it 'handles an absolute path with zero traversal depth twice' do
    collect_twice({ 'AutoCheck' => false, 'DEPTH' => 0 })
  end

  it 'preserves spaces and exact escaped file bytes twice' do
    collect_twice({ 'AutoCheck' => false, 'FILEPATH' => proof_root + 'space name.txt' })
  end

  it 'preserves a quoted filename in the submitted JSON twice' do
    collect_twice({ 'AutoCheck' => false, 'FILEPATH' => proof_root + 'quote"name.txt', 'HttpTrace' => true })
  end

  it 'reports missing and empty files without storing false loot' do
    %w[missing.txt empty.txt].each do |name|
      output = owner({ 'AutoCheck' => false, 'FILEPATH' => proof_root + name })
      expect(output).not_to include('Stored results in')
      expect(reports).to eq('loot' => [], 'vulns' => [])
    end
  end

  def native_control(phase)
    argv = ['python3', '-B', 'test/module_targets/netalertx_file_read/native_probe.py']
    output, error, status = Open3.capture3(*argv)
    artifacts = target_runtime.fetch('artifacts')
    File.write(File.join(artifacts, "native-status-#{phase}.json"), JSON.pretty_generate(argv: argv, exitstatus: status.exitstatus, stderr: error))
    source = File.join(artifacts, 'native-netalertx.json')
    FileUtils.cp(source, File.join(artifacts, "native-netalertx-#{phase}.json")) if File.file?(source)
    expect(status.success?).to be(true), error
    JSON.parse(output)
  end

  def version
    ENV.fetch('NETALERTX_VERSION')
  end

  def protected?
    ENV.fetch('NETALERTX_PROTECTED') == 'true'
  end

  def proof_root
    '/tmp/module-target-netalertx/'
  end

  def content
    "NetAlertX native proof\n<node>& \"quoted\"\nsecond line\n"
  end

  def owner(options, action: 'run')
    output = run_target_module('auxiliary/scanner/http/netalertx_file_read', 'target', { 'FILEPATH' => proof_root + 'proof.txt', 'THREADS' => 1, 'HttpClientTimeout' => 5 }.merge(options), action: action, allow_errors: true, command_timeout: 40)
    File.open(File.join(target_runtime.fetch('artifacts'), 'owning-calls.jsonl'), 'a') do |file|
      file.puts(JSON.generate(action: action, options: options, workspace: @workspace, output: output))
    end
    output
  end

  def collect_twice(options, exposed: @native.fetch('exposed'))
    2.times do |iteration|
      output = owner(options)
      data = reports
      unless exposed
        expect(output).not_to include('Stored results in')
        expect(data).to eq('loot' => [], 'vulns' => [])
        next
      end

      expect(output).to include('Stored results in')
      expect(data.fetch('loot').length).to eq(iteration + 1)
      data.fetch('loot').each do |row|
        expect(row.fetch('ltype')).to eq('netalert.results')
        expect(row.fetch('content_type')).to eq('text/plain')
        expect(row.fetch('address')).to eq(target_runtime.fetch('module_endpoints').fetch('target').fetch('host'))
        expect(File.binread(row.fetch('path'))).to eq(content)
      end
      automatic_report = version == '24.9.12' && !protected? && options.fetch('AutoCheck', true)
      # DBManager merges matching host/service/CVE reports and retains the first
      # record's name/info. AutoCheck reports before the collection does.
      expect(data.fetch('vulns').length).to eq(1)
      row = data.fetch('vulns').first
      expect(row.fetch('name').strip).to eq(automatic_report ? 'auxiliary/scanner/http/netalertx_file_read' : 'NetAlertX File Read Vulnerability')
      expect(row.fetch('address')).to eq(target_runtime.fetch('module_endpoints').fetch('target').fetch('host'))
      expect(row.fetch('refs')).to include('CVE-2024-48766')
      expected_info = if automatic_report
                        'This module exploits improper authentication in logs.php endpoint. An unathenticated attacker can request log file and read any file due path traversal vulnerability.'
                      else
                        'Module auxiliary/scanner/http/netalertx_file_read successfully leaked file'
                      end
      expect(row.fetch('info')).to eq(expected_info)
    end
  end

  def sql(query)
    target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
  end

  def reports
    raise ArgumentError, 'Invalid fixture workspace' unless @workspace.match?(/\Anetalertx_[0-9_]+\z/)

    query = <<~SQL
      SELECT json_build_object(
        'loot', (SELECT coalesce(json_agg(row), '[]'::json) FROM (
          SELECT loot.id, loot.path, loot.ltype, loot.content_type, host(host.address) AS address
          FROM loots loot JOIN workspaces workspace ON workspace.id=loot.workspace_id
          LEFT JOIN hosts host ON host.id=loot.host_id WHERE workspace.name='#{@workspace}' ORDER BY loot.id
        ) row),
        'vulns', (SELECT coalesce(json_agg(row), '[]'::json) FROM (
          SELECT vuln.name, vuln.info, host(host.address) AS address,
            ARRAY(SELECT ref.name FROM refs ref JOIN vulns_refs vr ON vr.ref_id=ref.id WHERE vr.vuln_id=vuln.id ORDER BY ref.name) refs
          FROM vulns vuln JOIN hosts host ON host.id=vuln.host_id
          JOIN workspaces workspace ON workspace.id=host.workspace_id WHERE workspace.name='#{@workspace}'
        ) row)
      );
    SQL
    data = JSON.parse(sql(query))
    File.open(File.join(target_runtime.fetch('artifacts'), 'report-snapshots.jsonl'), 'a') do |file|
      file.puts(JSON.generate(workspace: @workspace, reports: data))
    end
    data
  end
end
