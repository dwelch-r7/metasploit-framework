require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/php_reverse_php/native_probe'

fixture = JSON.parse(File.read(File.expand_path('../../../../../test/module_targets/php_reverse_php/cases.json', __dir__)))
matrix = nil
ready = false

group = RSpec.describe 'Native generated PHP reverse shell', acceptance: true do
  fixture.fetch('cases').each do |item|
    it item.fetch('name') do
      record = matrix.fetch('cases').find { |result| result.fetch('name') == item.fetch('name') }
      expect(record.fetch('errors')).to eq([]), JSON.pretty_generate(record)
      expect(record.fetch('exitstatus')).to eq(0)
      expect(record.fetch('reaped')).to be(true)
      expect(record.fetch('steps').size).to eq(5)
      record.fetch('steps').each do |step|
        expect(Base64.strict_decode64(step.fetch('actual_base64'))).to eq(Base64.strict_decode64(step.fetch('expected_base64')))
      end
      expect(Base64.strict_decode64(record.fetch('cwd_base64'))).to eq("/tmp\n")
      runtime = Base64.strict_decode64(record.fetch('stderr_base64')).lines.filter_map do |line|
        next unless line.start_with?('{')

        value = JSON.parse(line)
        value if value['kind'] == 'runtime'
      end
      expect(runtime.size).to eq(1)
      expect(runtime.first.fetch('php')).to eq('8.3.28')
      expect(runtime.first.fetch('fsockopen')).to eq(item.fetch('transport') == 'fsockopen')
      expect(runtime.first.fetch('socket_create')).to be(true)
    end
  end
end

RSpec.configure do |config|
  # Keep infrastructure errors separate from the 38 case results. This filter
  # check also prevents native work when default CI excludes acceptance cases.
  config.before(:suite) do
    next if config.dry_run? || group.descendant_filtered_examples.empty?

    path = ENV['MODULE_TARGET_RUNTIME']
    raise PHPReverseTarget::InfrastructureError, 'MODULE_TARGET_RUNTIME is required; use the guarded target runner' unless path

    runtime = JSON.parse(File.read(path))
    matrix = PHPReverseTarget::Probe.new(runtime).capture
    ready = true
  end

  config.after(:suite) do
    next unless ready

    errors = PHPReverseTarget::Probe.resource_errors(matrix, 'after')
    errors << 'Controller temporary files remain' unless matrix.fetch('temporary_files_removed')
    raise PHPReverseTarget::InfrastructureError, "Native postflight failed: #{errors.join('; ')}" unless errors.empty?
  end
end
