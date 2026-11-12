# frozen_string_literal: true

RSpec.shared_context 'pretalx reporting target' do
  include_context 'module target'

  before(:all) do
    @native = native('native')
    expect(@native.fetch('version')).to eq(ENV.fetch('PRETALX_VERSION'))
    expect(@native.fetch('debug')).to eq(debug?)
    expect(@native.fetch('exposed')).to eq(vulnerable?)
    expect(@native.fetch('source_hashes').length).to eq(12)
    expect(@native.fetch('asset_build')&.fetch('workers')).to eq(debug? ? 1 : nil)
    expect(console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
  end

  before do |example|
    @workspace = "pretalx_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(reports).to eq('loot' => [], 'vulns' => [])
  end

  after do
    File.open(File.join(target_runtime.fetch('artifacts'), 'owner-state.jsonl'), 'a') { |file| file.puts(JSON.generate(native('state'))) }
    %w[sessions jobs].each do |kind|
      expect(console_command("irb -e 'puts \"PRETALX_CLEAN=\" + framework.#{kind}.keys.to_json'")).to include('PRETALX_CLEAN=[]')
    end
  end

  after(:all) do
    %w[target broker framework reporting_db].each do |role|
      expect(target_exec(role, 'cat', '/sys/fs/cgroup/memory.events')).to include("oom 0\n", "oom_kill 0\n")
      expect(target_exec(role, 'cat', '/sys/fs/cgroup/pids.events').strip).to eq('max 0')
    end
  end

  def debug?
    ENV.fetch('PRETALX_DEBUG', 'false') == 'true'
  end

  def vulnerable?
    ENV.fetch('PRETALX_VERSION') == '2.3.1'
  end

  def native(mode)
    text = target_exec('target', 'python', '/lab/native.py', mode)
    data = JSON.parse(text.lines.last)
    File.open(File.join(target_runtime.fetch('artifacts'), 'native-controls.jsonl'), 'a') { |file| file.puts(JSON.generate(mode: mode, data: data)) }
    data
  end

  def owner(options = {}, action: 'run')
    defaults = {
      'EMAIL' => 'organizer@example.invalid', 'PASSWORD' => 'module-target-pretalx-password',
      'CONFERENCE_NAME' => 'validation', 'FILEPATH' => '/data/proof/proof.txt',
      'VHOST' => 'target', 'ExportTimeout' => 8, 'THREADS' => 1, 'HttpClientTimeout' => 20
    }
    output = run_target_module('auxiliary/scanner/http/pretalx_file_read_cve_2023_28459', 'target', defaults.merge(options), action: action, allow_errors: true, command_timeout: 100)
    File.open(File.join(target_runtime.fetch('artifacts'), 'owning-calls.jsonl'), 'a') { |file| file.puts(JSON.generate(action: action, options: options, output: output)) }
    output
  end

  def collect_twice(options, exposed: vulnerable?, content: "Pretalx exact file proof\n<node>& \"quoted\"\nsecond line\n")
    2.times do |iteration|
      output = owner(options)
      data = reports
      if exposed
        expect(output).to include('Stored results in')
        expect(data.fetch('loot').length).to eq(iteration + 1)
        data.fetch('loot').each do |row|
          expect(File.binread(row.fetch('path'))).to eq(content)
          expect(row.fetch('content_type')).to eq('text/plain')
        end
        expect(data.fetch('vulns').length).to eq(1)
        expect(data.fetch('vulns').first.fetch('refs')).to include('CVE-2023-28459')
      else
        expect(output).not_to include('Stored results in')
        expect(data).to eq('loot' => [], 'vulns' => [])
      end
    end
  end

  def reports
    raise ArgumentError, 'Invalid fixture workspace' unless @workspace.match?(/\Apretalx_[0-9_]+\z/)

    query = <<~SQL
      SELECT json_build_object(
        'loot', COALESCE((SELECT json_agg(json_build_object('path', path, 'ltype', ltype, 'content_type', content_type)) FROM loots WHERE workspace_id = (SELECT id FROM workspaces WHERE name = '#{@workspace}')), '[]'::json),
        'vulns', COALESCE((SELECT json_agg(json_build_object('name', name, 'info', info, 'refs', (SELECT COALESCE(json_agg(refs.name), '[]'::json) FROM refs INNER JOIN vulns_refs ON refs.id = vulns_refs.ref_id WHERE vulns_refs.vuln_id = vulns.id))) FROM vulns WHERE host_id IN (SELECT id FROM hosts WHERE workspace_id = (SELECT id FROM workspaces WHERE name = '#{@workspace}'))), '[]'::json));
    SQL
    JSON.parse(target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query))
  end
end
