# frozen_string_literal: true

require 'rbconfig'

component = File.expand_path(__dir__)
root = File.expand_path('../../..', component)
raise 'Spring Cloud Config artifact preparation failed' unless system(RbConfig.ruby, File.join(component, 'prepare.rb'))

families = %w[springcloud_2_1_8 springcloud_2_1_9 springcloud_2_2_2 springcloud_2_2_3]
exec(RbConfig.ruby, File.join(root, 'tools/dev/run_guarded_module_target_tests.rb'), *families)
