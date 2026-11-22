require 'acceptance_spec_helper'
require_relative '../../../test/module_targets/couchdb_erlang_sessions/acceptance'

# Record the fresh console's automatic selection before explicit family tests.
RSpec.describe 'CouchDB Erlang commands and sessions', order: :defined do
  include_context 'module target'
  include_context 'wait_for_expect'
  include Acceptance::CouchdbErlangSessions

  before(:all) { cs_boot }

  it 'uses explicit OpenSSL sessions twice and separately records automatic selection' do
    cs_owner('cmd/unix/reverse_openssl', 0, record_selection: true)
  end

  it 'uses the declared Linux x86 wget family twice after a native payload control' do
    cs_owner('linux/x86/meterpreter_reverse_tcp', 1)
  end

  it 'uses Linux x64 wget delivery twice after a native payload control' do
    cs_owner('linux/x64/meterpreter_reverse_tcp', 1)
  end

  it 'executes exact quoted ASCII commands twice with AutoCheck disabled' do
    cs_command("ASCII 'quote' \"double\" $literal ; tail", auto_check: false)
  end

  it 'preserves exact Unicode and CRLF commands twice through the real datastore' do
    cs_command("Unicode é λ 💥 'quote' \"double\"\r\nsecond line\n")
  end

  after(:all) { cs_finish if @cs }
end
