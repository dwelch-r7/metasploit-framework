# frozen_string_literal: true

# This runner owns its filters; the parent's SPEC_OPTS can conflict with them.
ENV.delete('SPEC_OPTS')

require 'rspec/core'
require 'rspec/expectations'
require 'json'
require 'digest'

project, report, selection = ARGV
$LOAD_PATH.unshift(project)
$LOADED_FEATURES << File.join(project, 'acceptance_spec_helper.rb')

# Synthetic console boundaries for exercising the real source lifecycle.
module SourceLifecycleFixture
  def lifecycle_event(name)
    File.open(ENV.fetch('SOURCE_LIFECYCLE_EVENTS'), 'a') { |file| file.puts(name) }
  end

  def source_override
    File.join(ENV.fetch('SOURCE_LIFECYCLE_ARTIFACTS'), 'msf-config/payloads/meterpreter/meterpreter.php')
  end

  # Verify real isolated file bytes; the Framework console and native target
  # are deliberately absent from this RSpec hook-lifecycle fixture.
  def rc_json(code)
    if code.start_with?('{path:')
      lifecycle_event('bind')
      { 'path' => source_override, 'sha256' => Digest::SHA256.file(source_override).hexdigest }
    else
      { 'synthetic_observer' => true }
    end
  end

  def rc_save
    lifecycle_event('save')
  end
end

RSpec.configure do |config|
  config.include SourceLifecycleFixture
  config.filter_run_excluding(acceptance: true)
end

arguments = ['--options', File::NULL, '--format', 'json', '--out', report]
arguments += case selection
             when 'content' then ['--tag', 'content']
             when 'acceptance' then ['--tag', 'acceptance']
             when 'dry-run' then ['--tag', 'acceptance', '--dry-run']
             else raise ArgumentError, 'Unknown lifecycle selection'
             end
arguments += [File.join(project, 'spec/modules/exploits/linux/http/projectsend_source_target_spec.rb'), File.join(project, 'unrelated_spec.rb')]
exit RSpec::Core::Runner.run(arguments)
