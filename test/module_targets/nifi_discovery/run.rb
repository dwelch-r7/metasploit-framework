# frozen_string_literal: true

require 'rbconfig'

root = File.expand_path('../../..', __dir__)
exec(RbConfig.ruby, File.join(root, 'tools/dev/run_guarded_module_target_tests.rb'), *%w[nifi_discovery nifi_discovery_vulnerable nifi_discovery_fixed])
