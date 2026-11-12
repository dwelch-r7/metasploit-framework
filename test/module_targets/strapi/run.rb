# frozen_string_literal: true

require 'rbconfig'

root = File.expand_path('../../..', __dir__)
Dir.chdir(root) do
  raise 'Strapi dependency preparation failed' unless system(RbConfig.ruby, 'test/module_targets/strapi/prepare.rb')

  exec(RbConfig.ruby, 'tools/dev/run_guarded_module_target_tests.rb', 'strapi_3_0_0_beta_17_4', 'strapi_3_0_0_beta_17_5')
end
