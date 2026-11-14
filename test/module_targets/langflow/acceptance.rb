# frozen_string_literal: true

require 'base64'
require 'digest'
require 'open3'

module Acceptance
  # Exercise the public console and compare its persisted JSON with vendor SDK data.
  module Langflow
    OWNER = 'auxiliary/gather/langflow_auth_bypass_cve_2026_93680'

    def langflow_record(name, data)
      File.open(File.join(target_runtime.fetch('artifacts'), name), 'a') { |file| file.puts(JSON.generate(data)) }
    end

    def langflow_native(action, tag)
      @native_call = (@native_call || 0) + 1
      arguments = ['python3', '-B', 'test/module_targets/langflow/native.py', action, "#{tag}-#{@native_call}"]
      output, error, status = Open3.capture3(*arguments)
      langflow_record('native-probe-status.jsonl', argv: arguments, actual_exit: status.exitstatus, stdout: output, stderr: error)
      expect(status.exitstatus).to eq(0), error
      JSON.parse(output)
    end

    def langflow_loot
      Dir[File.join(target_runtime.fetch('artifacts'), 'msf-config', 'loot', '**', '*')].select { |path| File.file?(path) }.sort
    end

    def langflow_reports
      raise ArgumentError, 'Invalid fixture workspace' unless @workspace.match?(/\Alangflow_[0-9_]+\z/)

      query = <<~SQL
        SELECT coalesce(json_agg(row ORDER BY row.id),'[]'::json) FROM (
          SELECT l.id,l.path,l.ltype,l.content_type,l.name,host(h.address::inet) AS host
          FROM loots l JOIN workspaces w ON w.id=l.workspace_id LEFT JOIN hosts h ON h.id=l.host_id
          WHERE w.name='#{@workspace}'
        ) row
      SQL
      rows = JSON.parse(target_exec('reporting_db', 'psql', '-U', 'module_framework', '-d', 'module_targets', '-Atc', query))
      langflow_record('database-loot.jsonl', workspace: @workspace, rows: rows)
      rows
    end

    def langflow_idle
      output = console_command(%q{irb -e 'puts "LANGFLOW_IDLE=" + [framework.sessions.keys,framework.jobs.keys].to_json'})
      expect(output).to include('LANGFLOW_IDLE=[[],[]]')
    end

    def langflow_call(options = {}, reuse: false)
      @call = (@call || 0) + 1
      before = langflow_loot
      endpoint = target_runtime.fetch('module_endpoints').fetch('target')
      settings = { 'SSETimeout' => 3, 'HttpClientTimeout' => 3, 'TARGETURI' => '/' }.merge(options)
      output = nil
      begin
        if reuse
          # No second use/back: the same selected owner must reset per-run state.
          datastore = { 'RHOSTS' => endpoint.fetch('host'), 'RPORT' => endpoint.fetch('port'), 'VERBOSE' => true }.merge(settings)
          output = console_command('run ' + format_datastore_options(datastore), timeout: 40)
          expect(output).not_to match(/Exception|undefined method|Unknown command|Msf::OptionValidateError/)
          expect(output).to include('Auxiliary module execution completed')
        else
          output = run_target_module(OWNER, 'target', settings, allow_errors: true, command_timeout: 40)
        end
      ensure
        captured = (output || console.all_data).dup.force_encoding(Encoding::UTF_8)
        encoding = captured.valid_encoding? ? 'utf-8' : 'base64'
        langflow_record('owning-calls.jsonl', owner: OWNER, workspace: @workspace, call: @call, options: settings,
                                              same_selected_instance: reuse, wrapper_returned: !output.nil?, output_encoding: encoding,
                                              output: encoding == 'utf-8' ? captured : Base64.strict_encode64(captured), new_loot: langflow_loot - before)
      end
      expect(output).not_to include('Unknown datastore option')
      langflow_idle
      [output, langflow_loot - before]
    end

    def langflow_collect(reuse: false)
      output, paths = langflow_call({}, reuse: reuse)
      expect(output).not_to match(/Auxiliary (?:failed|aborted)/)
      expect(output).to include('MCP initialize accepted (HTTP 202)', 'MCP initialized notification accepted (HTTP 202)', 'MCP tools/list accepted (HTTP 202)')
      expect(paths.length).to eq(1)
      session_id = output[/MCP session ID: ([A-Za-z0-9._~-]+)/, 1]
      expect(session_id).not_to be_nil
      expect(@mcp_ids || []).not_to include(session_id)
      (@mcp_ids ||= []) << session_id
      path = paths.fetch(0)
      expect(output).to include('Langflow MCP information stored in loot: ' + path)
      actual = JSON.parse(File.binread(path))
      actual.fetch('mcp').fetch('tools').sort_by! { |tool| tool.fetch('name') }
      initialize_result = @native.fetch('sdk').fetch('initialize')
      endpoint = target_runtime.fetch('module_endpoints').fetch('target')
      expected = {
        'target' => { 'host' => endpoint.fetch('host'), 'port' => 7860, 'ssl' => false, 'target_uri' => '/' },
        'mcp' => {
          'protocol_version' => initialize_result.fetch('protocolVersion'),
          'server' => initialize_result.fetch('serverInfo'),
          'capabilities' => initialize_result.fetch('capabilities'),
          'tools' => @native.fetch('sdk').fetch('tools').fetch('tools').sort_by { |tool| tool.fetch('name') }
        }
      }
      expect(actual).to eq(expected)
      expect(langflow_reports.last).to include('path' => path, 'ltype' => 'langflow.mcp', 'content_type' => 'application/json', 'name' => 'mcp_info.json', 'host' => endpoint.fetch('host'))
      langflow_record('loot-proofs.jsonl', path: path, sha256: Digest::SHA256.file(path).hexdigest,
                                           json_matches_native: true, tool_count: expected.fetch('mcp').fetch('tools').length, mcp_session_id: session_id)
    end
  end
end
