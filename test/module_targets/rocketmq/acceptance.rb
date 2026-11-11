# frozen_string_literal: true

require_relative '../../../tools/dev/run_module_target_tests'

module Acceptance
  # The vendor SDK supplies independent version, route and execution controls.
  module Rocketmq
    SCANNER = 'auxiliary/scanner/misc/rocketmq_version'
    EXPLOIT = 'exploit/multi/http/apache_rocketmq_update_config'

    def rocketmq_native(role, phase, action = 'snapshot')
      output = +''
      path = File.join(target_runtime.fetch('artifacts'), "native-#{phase}-#{role}")
      argv = target_runtime.fetch('compose') + ['exec', '-T', role, 'bash', '/lab/native.sh', action]
      passed = ModuleTargetTests.new.send(:command, argv, path: "#{path}.log", timeout: 90, capture: output, quiet: true)
      lines = output.lines.grep(/^NATIVE_JSON=/)
      expect(passed).to be(true), output
      expect(lines.size).to eq(1), output
      native = JSON.parse(lines.first.delete_prefix('NATIVE_JSON='))
      File.write("#{path}.json", JSON.pretty_generate(native) + "\n")
      native
    end

    def rocketmq_call(kind, role, options = {}, allow_errors: false)
      @rocketmq_call = (@rocketmq_call || 0) + 1
      example = RSpec.current_example.id.split('[', 2).last.delete_suffix(']').tr(':', '-')
      path = File.join(target_runtime.fetch('artifacts'), "owning-#{example}-#{@rocketmq_call}.json")
      observed = File.join(target_runtime.fetch('artifacts'), 'msf-config/rocketmq-wire.jsonl')
      offset = File.file?(observed) ? File.readlines(observed).size : 0
      endpoint = target_runtime.fetch('module_endpoints').fetch(role)
      console_command('back')
      selected = console_command("use #{kind == 'scan' ? SCANNER : EXPLOIT}")
      expect(selected).not_to match(/Failed to load|Unknown command|No results/)
      datastore = { 'RHOSTS' => endpoint.fetch('host'), 'RPORT' => endpoint.fetch('port'), 'VERBOSE' => true, 'ConnectTimeout' => 3 }
      datastore['THREADS'] = 1 if kind == 'scan'
      output = console_command("#{kind == 'scan' ? 'run' : 'check'} #{format_datastore_options(datastore.merge(options))}", timeout: 40)
      wire = File.file?(observed) ? File.readlines(observed).drop(offset).map { |line| JSON.parse(line) } : []
      File.write(path, JSON.pretty_generate(kind: kind, role: role, options: options, output: output, wire: wire) + "\n")
      expect(output).not_to match(/Auxiliary failed:|Check failed:|undefined method|Unknown command|Unknown datastore option|Msf::OptionValidateError/)
      expect(output).to include('Auxiliary module execution completed') if kind == 'scan'
      expect(output).not_to include('[-]') unless allow_errors
      [output, wire]
    end
  end
end
