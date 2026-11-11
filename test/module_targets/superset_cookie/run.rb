#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative '../../../tools/dev/run_guarded_module_target_tests'

# Preserve the component command while sharing manifest-driven selection.
class SupersetCookieRunner < GuardedModuleTargetTests
end

if $PROGRAM_NAME == __FILE__
  abort 'Usage: bundle exec ruby test/module_targets/superset_cookie/run.rb' unless ARGV.empty?
  exit SupersetCookieRunner.new.run(['superset_cookie'])
end
