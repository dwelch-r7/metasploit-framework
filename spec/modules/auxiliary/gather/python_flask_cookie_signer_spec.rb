require 'rspec'
require 'rex/text'
require_relative '../../../../lib/msf/core/exploit/remote/http/flask_unsign'

RSpec.describe 'Python Flask cookie signer session content' do
  let(:signer) { Msf::Exploit::Remote::HTTP::FlaskUnsign::Session }
  let(:failure_class) { Class.new(StandardError) }
  let(:messages) { [] }
  let(:options) do
    {
      'NEWCOOKIECONTENT' => '{"user_id":1}', 'CookieContentFormat' => 'String',
      'SECRET' => 'module-target-public-test-secret', 'Salt' => 'cookie-session', 'CookieName' => 'session'
    }
  end

  # Evaluate the complete owner source, with explicit auxiliary/HTTP/UI
  # boundaries. No Framework instance, module initialization or transport runs.
  # The real run branch and real signer/decoder are exercised below.
  let(:mod) do
    failure = Module.new
    failure.const_set(:BadConfig, 'bad-config')
    auxiliary = Class.new do
      attr_accessor :datastore, :action, :peer

      def print_status(_message); end
      def print_good(_message); end
      def fail_with(_reason, _message); end
    end
    auxiliary.const_set(:Failure, failure)
    msf = Module.new
    msf.const_set(:Auxiliary, auxiliary)
    exploit = Module.new
    remote = Module.new
    remote.const_set(:HttpClient, Module.new)
    http = Module.new
    http.const_set(:FlaskUnsign, Msf::Exploit::Remote::HTTP::FlaskUnsign)
    remote.const_set(:HTTP, http)
    exploit.const_set(:Remote, remote)
    msf.const_set(:Exploit, exploit)
    scope = Module.new
    scope.const_set(:Msf, msf)
    path = File.expand_path('../../../../modules/auxiliary/gather/python_flask_cookie_signer.rb', __dir__)
    scope.module_eval(File.read(path), path)
    scope.const_get(:MetasploitModule).allocate
  end

  before do
    mod.datastore = options
    mod.action = double('Resign action', name: 'Resign')
    mod.peer = '192.0.2.1:80'
    allow(mod).to receive(:print_good) { |message| messages << message }
    allow(mod).to receive(:fail_with) { |reason, message| raise failure_class, "#{reason}: #{message}" }
    allow(Time).to receive(:now).and_return(Time.utc(2026, 11, 11))
  end

  def signed_cookie
    mod.run
    messages.fetch(0).match(/New signed cookie: session=(\S+)\z/).captures.fetch(0)
  end

  it 'preserves the exact prior String-mode cookie bytes' do
    expected = signer.sign(options.fetch('NEWCOOKIECONTENT'), options.fetch('SECRET'), salt: options.fetch('Salt'))

    expect(signed_cookie).to eq(expected)
  end

  it 'keeps JSON-looking String content as literal text' do
    expect(signer.decode(signed_cookie)).to eq('{"user_id":1}')
  end

  it 'preserves literal text for callers that do not supply the new option' do
    options.delete('CookieContentFormat')

    expect(signer.decode(signed_cookie)).to eq('{"user_id":1}')
  end

  it 'preserves the prior String-mode cookie bytes for nil content' do
    options['NEWCOOKIECONTENT'] = nil
    expected = signer.sign(nil, options.fetch('SECRET'), salt: options.fetch('Salt'))

    expect(signed_cookie).to eq(expected)
  end

  it 'keeps the documented Ruby-hash-looking String content as literal text' do
    options['NEWCOOKIECONTENT'] = '{"user_id"=>1}'

    expect(signer.decode(signed_cookie)).to eq('{"user_id"=>1}')
  end

  it 'signs a nested JSON session object without converting it to a String' do
    options['CookieContentFormat'] = 'JSON'
    options['NEWCOOKIECONTENT'] = '{"user_id":1,"context":{"roles":["Admin"],"active":true,"optional":null},"locale":"fr"}'
    expected = { 'user_id' => 1, 'context' => { 'roles' => ['Admin'], 'active' => true, 'optional' => nil }, 'locale' => 'fr' }

    expect(signer.decode(signed_cookie)).to eq(expected)
  end

  it 'accepts an empty JSON session object' do
    options['CookieContentFormat'] = 'JSON'
    options['NEWCOOKIECONTENT'] = '{}'

    expect(signer.decode(signed_cookie)).to eq({})
  end

  {
    'missing content' => [nil, 'must contain JSON text'],
    'malformed JSON' => ['{', 'must be valid JSON'],
    'Ruby hash syntax' => ['{"user_id"=>1}', 'must be valid JSON'],
    'a top-level string' => ['"user_id"', 'must be a JSON object'],
    'a top-level array' => ['[1]', 'must be a JSON object'],
    'a top-level null' => ['null', 'must be a JSON object'],
    'a top-level number' => ['1', 'must be a JSON object'],
    'a top-level boolean' => ['false', 'must be a JSON object']
  }.each do |description, (content, reason)|
    it "rejects #{description} in JSON mode before signing" do
      options['CookieContentFormat'] = 'JSON'
      options['NEWCOOKIECONTENT'] = content
      expect(signer).not_to receive(:sign)

      expect { mod.run }.to raise_error(failure_class, /bad-config: NEWCOOKIECONTENT #{reason}/)
    end
  end
end
