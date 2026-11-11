#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative '../../../tools/dev/run_guarded_module_target_tests'

if $PROGRAM_NAME == __FILE__
  raise ArgumentError, 'This launcher selects only the Superset RCE owner profile' unless ARGV.empty?

  exit(GuardedModuleTargetTests.new.run(['superset_rce_owner']) ? 0 : 1)
end
