# frozen_string_literal: true

require_relative '../../../tools/dev/run_module_target_tests'

module Acceptance
  # Compare printed model data with independently validated native CLI/API state.
  module Ollama
    OWNER = 'auxiliary/scanner/http/ollama_info'

    def ollama_native(phase, state = 'baseline')
      @ollama_native_calls = (@ollama_native_calls || 0) + 1
      example = RSpec.current_example&.id&.split('[', 2)&.last&.delete_suffix(']')&.tr(':', '-') || 'all'
      name = "native-#{phase}-#{example}-#{@ollama_native_calls}"
      path = File.join(target_runtime.fetch('artifacts'), name)
      proxy = target_runtime.fetch('module_endpoints').fetch('proxy').fetch('host')
      argv = target_runtime.fetch('compose') + ['exec', '-T', '--env', "MODULE_TARGET_PROXY_HOST=#{proxy}", 'ollama', 'python3', '/lab/native_probe.py', phase, state]
      output = +''
      passed = ModuleTargetTests.new.send(:command, argv, path: "#{path}.log", timeout: 150, capture: output, quiet: true)
      File.write("#{path}.json", output)
      expect(passed).to be(true), output
      native = JSON.parse(output)
      expect(native.fetch('status')).to eq('native_passed')
      native
    end

    def ollama_scan(service = 'ollama', options = {}, allow_errors: false)
      @ollama_call = (@ollama_call || 0) + 1
      example = RSpec.current_example.id.split('[', 2).last.delete_suffix(']').tr(':', '-')
      path = File.join(target_runtime.fetch('artifacts'), "owning-#{example}-#{@ollama_call}.json")
      observed = File.join(target_runtime.fetch('artifacts'), 'msf-config/ollama-http.jsonl')
      before = File.file?(observed) ? File.readlines(observed).size : 0
      endpoint = target_runtime.fetch('module_endpoints').fetch(service)
      console_command('back')
      selected = console_command("use #{OWNER}")
      expect(selected).not_to match(/Failed to load|Unknown command|No results/)
      datastore = {
        'TARGETURI' => '/', 'HttpUsername' => '', 'HttpPassword' => '',
        'RHOSTS' => endpoint.fetch('host'), 'RPORT' => endpoint.fetch('port'), 'VERBOSE' => true, 'THREADS' => 1,
        'ConnectTimeout' => 3, 'HttpClientTimeout' => 5
      }.merge(options)
      output = console_command("run #{format_datastore_options(datastore)}", timeout: 35)
      replies = File.file?(observed) ? File.readlines(observed).drop(before).map { |line| JSON.parse(line) } : []
      File.write(path, JSON.pretty_generate(service: service, options: options, output: output, replies: replies) + "\n")
      expect(output).to include('Auxiliary module execution completed')
      expect(output).not_to match(/Auxiliary failed:|undefined method|Unknown command|Msf::OptionValidateError/)
      expect(output).not_to include('[-]') unless allow_errors
      [output, replies]
    end

    def verify_ollama_table(native, service = 'ollama', options = {}, details_denied: false)
      output, replies = ollama_scan(service, options, allow_errors: details_denied)
      snapshot = native.fetch('snapshot')
      active = snapshot.fetch('running').to_h { |model| [model.fetch('name'), model] }
      names = snapshot.fetch('models').map { |model| model.fetch('name') }
      rows = output.lines.map(&:strip).select { |line| line.start_with?('lab-running ', 'lab-installed ') }
      expect(rows.size).to eq(names.size)
      snapshot.fetch('models').each do |model|
        name, tag = model.fetch('name').split(':', 2)
        row = rows.find { |line| line.start_with?("#{name} ") }
        expect(row).not_to be_nil
        columns = row.split(/\s+/, 8)
        source = active.fetch(model.fetch('name'), model)
        expect(source.fetch('size')).to be_between(1024**2, 1024**3 - 1)
        expect(columns.first(5)).to eq([name, tag, active.key?(model.fetch('name')) ? 'Running' : 'Installed', format('%.2f', source.fetch('size') / 1024.0**2), 'MB'])
        details = snapshot.fetch('details').fetch(model.fetch('name'))
        parameter_size = details_denied ? 'N/A' : details.fetch('details').fetch('parameter_size')
        temperature = details_denied || !details.fetch('parameters', '').include?('temperature') ? 'N/A' : '0.42'
        expect(columns[5, 2]).to eq([parameter_size, temperature])
        system = details_denied ? '' : details.fetch('system', '')
        if system.empty?
          expect(columns[7].strip).to eq('N/A')
        else
          system.lines.each { |line| expect(output).to include(line.strip) }
        end
      end
      expect(output).to include('Ollama Models', 'Parameter Size', 'System Prompt')
      expect(replies.map { |reply| reply.fetch('uri') }).to include(options.fetch('TARGETURI', '/'))
      if details_denied
        expect(replies.count { |reply| reply['code'] == 401 }).to eq(names.size)
      end
    end
  end
end
