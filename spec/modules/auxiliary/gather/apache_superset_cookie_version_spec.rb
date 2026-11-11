require 'rspec'
require 'rex/text'
require 'rex/version'

RSpec.describe 'Superset default-key version checks' do
  fragment = File.read(File.expand_path('../../../file_fixtures/modules/superset/login_version_fragment.html', __dir__))

  # Evaluate complete owner sources with explicit HTTP/superclass/CheckCode
  # boundaries. No Framework instance, initialization, transport or exploit runs.
  # The marker is copied from a genuine 2.0.1 native login response; replacing
  # its version tests comparisons, not native behavior on the other releases.
  def check_owner(path, response)
    base = Class.new do
      def send_request_cgi!(_options); end
      def normalize_uri(*parts) = parts.join('/')
      def target_uri = Struct.new(:path).new('/')
      def peer = '192.0.2.1:80'
    end
    remote = Class.new(base)
    remote.const_set(:HttpClient, Module.new)
    remote.const_set(:AutoCheck, Module.new)
    result = Struct.new(:code, :reason)
    codes = Module.new
    %i[Unknown Safe Appears].each do |name|
      codes.define_singleton_method(name) { |reason| result.new(name, reason) }
    end
    exploit = Module.new
    exploit.const_set(:Remote, remote)
    exploit.const_set(:CheckCode, codes)
    msf = Module.new
    msf.const_set(:Auxiliary, Class.new(base))
    msf.const_set(:Exploit, exploit)
    scope = Module.new
    scope.const_set(:Msf, msf)
    scope.const_set(:Exploit, exploit)
    scope.const_set(:GoodRanking, 300)
    source = File.expand_path("../../../../#{path}", __dir__)
    scope.module_eval(File.read(source), source)
    mod = scope.const_get(:MetasploitModule).allocate
    allow(mod).to receive(:send_request_cgi!).and_return(response)
    mod.check
  end

  %w[
    modules/auxiliary/gather/apache_superset_cookie_sig_priv_esc.rb
    modules/exploits/linux/http/apache_superset_cookie_sig_rce.rb
  ].each do |path|
    context path do
      {
        '1.4.0' => :Safe,
        '1.4.1' => :Appears,
        '2.0.0' => :Appears,
        '2.0.1' => :Appears,
        '2.1.0' => :Safe,
        '2.1.1' => :Safe
      }.each do |version, expected|
        it "returns #{expected} for version #{version}" do
          response = double('Login response boundary', code: 200, body: fragment.sub('2.0.1', version))
          checked = check_owner(path, response)

          expect([checked.code, checked.reason]).to eq([expected, "Apache Supset #{version} is #{expected == :Safe ? 'NOT ' : ''}vulnerable"])
        end
      end

      it 'returns reason-bearing Unknown when the target does not respond' do
        checked = check_owner(path, nil)

        expect([checked.code, checked.reason]).to eq([:Unknown, '192.0.2.1:80 - Could not connect to web service - no response'])
      end

      it 'returns reason-bearing Unknown for an unexpected HTTP status' do
        checked = check_owner(path, double('HTTP refusal boundary', code: 404))

        expect([checked.code, checked.reason]).to eq([:Unknown, '192.0.2.1:80 - Unexpected response code (404)'])
      end

      it 'does not identify a response without the application version marker' do
        checked = check_owner(path, double('Unrelated response boundary', code: 200, body: '<html>Unrelated application</html>'))

        expect([checked.code, checked.reason]).to eq([:Safe, '192.0.2.1:80 - Unexpected response, version_string not detected'])
      end

      it 'does not accept a version marker outside the observed encoded format' do
        checked = check_owner(path, double('Malformed marker boundary', code: 200, body: 'version_string=2.0.1'))

        expect([checked.code, checked.reason]).to eq([:Safe, '192.0.2.1:80 - Unexpected response, unable to determine version_string'])
      end
    end
  end
end
