# frozen_string_literal: true

require 'rbconfig'

root = File.expand_path('../../..', __dir__)
exec(RbConfig.ruby, File.join(root, 'tools/dev/run_guarded_module_target_tests.rb'), *%w[concretecms_9_5_0 concretecms_9_5_0_prefix concretecms_9_5_1 concretecms_unrelated])
