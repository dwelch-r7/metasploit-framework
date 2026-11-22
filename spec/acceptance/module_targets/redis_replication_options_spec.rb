require 'acceptance_spec_helper'
require_relative '../../../test/module_targets/redis_replication_options/acceptance'

RSpec.describe 'Genuine Redis encoded and custom-name owner', order: :defined do
  include_context 'module target'
  include_context 'wait_for_expect'
  include Acceptance::RedisReplicationOptions

  before(:all) { rr_boot }

  it 'uses and closes XOR-encoded default sessions twice' do
    2.times { |index| rro_run('encoded', index) }
  end

  it 'uses custom module names and a spaced Unicode filename twice' do
    2.times { |index| rro_run('named', index, names: true) }
  end

  after(:all) { rr_finish if @rr }
end
