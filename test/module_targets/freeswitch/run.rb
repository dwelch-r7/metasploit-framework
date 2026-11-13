# frozen_string_literal: true

require 'rbconfig'

root = File.expand_path('../../..', __dir__)
exec(RbConfig.ruby, File.join(root, 'tools/dev/run_guarded_module_target_tests.rb'), *%w[freeswitch_default freeswitch_custom freeswitch_acl freeswitch_unrelated])
