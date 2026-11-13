# frozen_string_literal: true

require 'rbconfig'

root = File.expand_path('../../..', __dir__)
exec(RbConfig.ruby, File.join(root, 'tools/dev/run_guarded_module_target_tests.rb'), *%w[freeswitch_exec_default freeswitch_exec_custom freeswitch_exec_acl freeswitch_exec_unrelated])
