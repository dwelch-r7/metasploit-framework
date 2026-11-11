# frozen_string_literal: true

# Isolated registration contract: full acceptance_spec_helper loads Framework.
# Use its genuine pure shared helpers; never execute their runtime hooks.
require 'rspec'
require 'json'
require 'test_prof/recipes/rspec/let_it_be'

root = Dir.pwd
$LOAD_PATH.unshift(File.join(root, 'spec'))
require File.join(root, 'spec/support/acceptance/datastore_formatting')
require File.join(root, 'spec/support/acceptance/module_target')
require File.join(root, 'spec/support/shared/contexts/wait_for_expect')
$LOADED_FEATURES << File.join(root, 'spec/acceptance_spec_helper.rb')

# Reject unexpected Framework loading rather than silently booting it in a test.
module NoFrameworkDiscovery
  def require(feature)
    raise LoadError, "Framework forbidden in isolated discovery: #{feature}" if feature.match?(%r{\A(?:msf(?:/|$)|metasploit/framework|config/environment)})

    super
  end
end
Kernel.prepend(NoFrameworkDiscovery)

# Dry registration cannot start a console, Docker command or target process.
module NoDiscoveryProcesses
  def spawn(*)
    raise 'Process execution forbidden in isolated discovery'
  end
end
Process.singleton_class.prepend(NoDiscoveryProcesses)

RSpec.configure do |config|
  config.define_derived_metadata(file_path: %r{spec/acceptance/}) { |metadata| metadata[:acceptance] = true }
  config.filter_run_excluding(acceptance: true)
end

mode, report = ARGV
raise ArgumentError, 'Expected excluded or included discovery mode' unless %w[excluded included].include?(mode)

arguments = ['--options', '/dev/null', '--dry-run', '--format', 'json', '--out', report]
arguments += ['--tag', 'acceptance'] if mode == 'included'
arguments << File.join(root, 'spec/acceptance/module_targets/minio_spec.rb')
code = RSpec::Core::Runner.run(arguments)
raise 'Framework was loaded by discovery' if defined?(Msf) || $LOADED_FEATURES.any? { |path| path.match?(%r{/lib/(?:msf/|metasploit/framework(?:[/.]|$))}) }

puts 'MINIO_ISOLATED_DISCOVERY_ONLY_NO_FRAMEWORK_OR_PROCESSES'
exit code
