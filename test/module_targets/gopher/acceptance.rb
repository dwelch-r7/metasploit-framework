# frozen_string_literal: true

require 'csv'
require_relative '../../../tools/dev/run_module_target_tests'

module Acceptance
  # Native menus supply expected selectors, text and persisted response bytes.
  module GopherTarget
    OWNER = 'auxiliary/scanner/gopher/gopher_gophermap'
    TYPES = { '0' => 'Text file', '1' => 'Directory', '3' => 'Error' }.freeze

    def native_gopher(phase)
      argv = ['python3', 'test/module_targets/gopher/native_probe.py', ENV.fetch('MODULE_TARGET_RUNTIME'), phase]
      output = +''
      passed = ModuleTargetTests.new.send(:command, argv, path: File.join(target_runtime.fetch('artifacts'), "native-#{phase}.log"), timeout: 90, capture: output, quiet: true)
      expect(passed).to be(true), output
      JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), "native-#{phase}.json")))
    end

    def gopher_call(selector = '', options: {})
      values = { 'PATH' => selector, 'THREADS' => 1 }.merge(options)
      output = run_target_module(OWNER, 'target', values, allow_errors: true, command_timeout: 60)
      text = output.dup.force_encoding(Encoding::UTF_8)
      expect(text.valid_encoding?).to be(true)
      File.open(File.join(target_runtime.fetch('artifacts'), 'owning-calls.jsonl'), 'a') do |file|
        file.puts(JSON.generate(selector: selector, options: options, workspace: @workspace, output: text))
      end
      expect(text).not_to include('Unknown datastore option')
      text
    end

    def verify_menu(selector = '')
      menu = @native.fetch('responses').fetch(selector)
      output = gopher_call(selector)
      menu.fetch('rows').each do |row|
        description = row.fetch('description')
        if row.fetch('type') == 'i'
          expect(output).to include("- #{description}\n")
        else
          expect(output).to include("-   #{TYPES.fetch(row.fetch('type'))}: #{description}\n")
          expect(output).to include("-     Path: #{row.fetch('host')}:#{row.fetch('port')}#{row.fetch('selector')}\n")
        end
      end
      expect(output).not_to include('[-]', 'Invalid File Type', 'No gophermap')
      expect(service_rows.map { |row| row.fetch('info') }).to eq([menu.fetch('text')])
      output
    end

    def report_sql(query)
      target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
    end

    def service_rows
      raise ArgumentError, 'Invalid fixture workspace' unless @workspace.match?(/\Agopher_[0-9_]+\z/)

      query = <<~SQL
        SELECT coalesce(json_agg(row ORDER BY row.id), '[]'::json) FROM (
          SELECT s.id, host(h.address::inet) AS host, s.port, s.proto, s.name, s.state, s.info
          FROM services s JOIN hosts h ON h.id=s.host_id JOIN workspaces w ON w.id=h.workspace_id
          WHERE w.name='#{@workspace}'
        ) row
      SQL
      rows = JSON.parse(report_sql(query))
      File.open(File.join(target_runtime.fetch('artifacts'), 'native-service-snapshots.jsonl'), 'a') do |file|
        file.puts(JSON.generate(workspace: @workspace, rows: rows))
      end
      rows
    end
  end
end
