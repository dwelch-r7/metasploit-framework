# frozen_string_literal: true

require 'rbconfig'

root = File.expand_path('../../..', __dir__)
exec(RbConfig.ruby, File.join(root, 'tools/dev/run_guarded_module_target_tests.rb'), *%w[freeswitch_sessions_default freeswitch_sessions_custom freeswitch_dropper_curl freeswitch_dropper_wget])
