# frozen_string_literal: true

require 'rbconfig'

component = File.expand_path(__dir__)
root = File.expand_path('../../..', component)
raise 'Dolibarr preparation failed' unless system(RbConfig.ruby, File.join(component, 'prepare.rb'))

families = %w[dolibarr_16_0_4 dolibarr_16_0_4_prefix dolibarr_16_0_5 dolibarr_16_0_5_lookup dolibarr_unrelated]
exec(RbConfig.ruby, File.join(root, 'tools/dev/run_guarded_module_target_tests.rb'), *families)
