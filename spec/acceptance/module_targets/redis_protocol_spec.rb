require 'acceptance_spec_helper'
require_relative '../../../test/module_targets/redis_protocol_utf8/acceptance'

RSpec.describe 'Redis protocol native-gated consumers', acceptance: true, order: :defined do
  include_context 'module target'
  include RedisProtocolTarget

  before(:all) { @rc = { commands: [], native: [], calls: [], attempts: [] } }

  before do |example|
    skip 'Native Redis protocol prerequisites failed; consumer verdict withheld' unless example.metadata[:native] || @rc[:protocol_prepared]
  end

  it('qualifies the real package, credentials, Unicode/binary data and file writes', native: true) { rp_ready }
  it('discovers INFO and PING through console and typed UTF-8 credentials') { rp_server }
  it('validates wrong and correct UTF-8 credentials with same-selection recovery') { rp_login }
  it('extracts exact Unicode, NUL, CRLF, empty and structured values into real loot twice') { rp_extract }
  it('uploads twice to Unicode filenames while restoring configuration and data') { rp_upload }
  it('checks the original Lua owner twice using typed UTF-8 credentials') { rp_check }
  it('preserves the original service identity, complete configuration and serialized keys') { rl_idle }

  after(:all) { rl_cleanup }
end
