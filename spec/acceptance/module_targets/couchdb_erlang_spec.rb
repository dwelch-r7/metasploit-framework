require 'acceptance_spec_helper'
require 'rbconfig'

RSpec.describe 'Genuine CouchDB Erlang owner' do
  include_context 'module target'
  include_context 'wait_for_expect'

  before(:all) do
    console_command('version')
    argv = [RbConfig.ruby, 'test/module_targets/couchdb_erlang/native_probe.rb']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-couchdb-erlang.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-couchdb-erlang-status.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exit: status.exitstatus))
    expect(status.success?).to be(true), stdout + stderr
  end

  it 'checks the independently authenticated native CouchDB node' do
    output = run_target_module('exploit/multi/http/apache_couchdb_erlang_rce', 'target', { 'WfsDelay' => 0 }, action: 'check')
    expect(output).to include('Successfully connected to the Erlang Server with cookie: "monster"')
  end

  it 'executes a benign ASCII command twice as the actual service user' do
    path = '/tmp/module-target-couchdb-owner'
    begin
      2.times do
        target_exec('target', 'test', '!', '-e', path)
        run_target_module('exploit/multi/http/apache_couchdb_erlang_rce', 'target', {
          'TARGET' => 0, 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => "printf %s couchdb-owner > #{path}",
          'WfsDelay' => 0, 'DisablePayloadHandler' => true
        })
        wait_for_expect(15, 0.1) { expect(target_exec('target', 'sh', '-c', "if test -f #{path}; then stat -c %u #{path}; fi").strip).to eq('5984') }
        expect(target_exec('target', 'cat', path)).to eq('couchdb-owner')
        target_exec('target', 'rm', path)
      end
    ensure
      target_exec('target', 'rm', '-f', path)
    end
  end
end
