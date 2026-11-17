require 'msfenv'
require 'msf/base'

RSpec.describe 'MasterStudy capabilities table prefix' do
  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('MASTERSTUDY_OWNER_SOURCE', File.expand_path('../../../../../modules/auxiliary/admin/http/wp_masterstudy_privesc.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:mod) { owner_class.new }
  let(:framework) { double('Framework', datastore: Msf::DataStore.new) }
  let(:requests) { [] }
  # Exact nonce fragment captured from the genuine MasterStudy 2.7.5 frontend
  # in the nondefault lab_ prefix reproduction. These HTTP objects are doubles
  # of that frontend fragment and the observed registration success response.
  let(:frontend) { Rex::Proto::Http::Response.new(200).tap { |response| response.body = '{"stm_lms_register":"13259520e4"}' } }
  let(:registration) do
    Rex::Proto::Http::Response.new(200).tap do |response|
      response.body = '{"message":"Registration completed successfully.","status":"success","user_page":"http:\/\/module-target.test\/"}'
    end
  end

  before do
    allow(mod).to receive(:framework).and_return(framework)
    mod.datastore.merge!(
      'RHOST' => '192.0.2.10',
      'RPORT' => 80,
      'TARGETURI' => '/',
      'USERNAME' => 'module_masterstudy_owned',
      'PASSWORD' => 'Module-study+2026!',
      'EMAIL' => 'module-masterstudy-owned@example.test'
    )
    allow(mod).to receive(:wordpress_and_online?).and_return(true)
    allow(mod).to receive(:check_plugin_version_from_readme).and_return(Msf::Exploit::CheckCode::Appears('Synthetic unit target version 2.7.5'))
    allow(mod).to receive(:send_request_cgi) do |request|
      requests << request
      request['method'] == 'POST' ? registration : frontend
    end
    allow(mod).to receive(:myworkspace_id).and_return(1)
    allow(mod).to receive(:create_credential)
    allow(mod).to receive(:report_vuln)
    allow(mod).to receive(:print_status)
    allow(mod).to receive(:print_good)
  end

  describe 'DB_PREFIX option' do
    let(:option) { mod.options['DB_PREFIX'] }

    it 'registers an advanced option with the compatible default' do
      expect(option).to have_attributes(advanced?: true, required?: true, default: 'wp_')
    end

    it 'accepts the native letters, numbers and underscores' do
      expect(option&.valid?('Lab_2_')).to be(true)
    end

    it 'accepts the empty prefix supported by WordPress' do
      expect(option&.valid?('')).to be(true)
    end

    it 'rejects an unset prefix' do
      expect(option&.valid?(nil)).to be(false)
    end

    {
      'dashes' => 'lab-',
      'dots' => 'lab.',
      'spaces' => 'lab prefix',
      'non-ASCII letters' => 'láb_',
      'embedded newlines' => "lab_\nwp_"
    }.each do |label, value|
      it "rejects #{label}" do
        expect(option&.valid?(value)).to be(false)
      end
    end
  end

  describe '#run registration request' do
    subject(:fields) do
      mod.run
      JSON.parse(requests.last.fetch('data')).fetch('profile_default_fields_for_register')
    end

    # Availability/version discovery, HTTP transport, output and database
    # reporting are doubled. Real owner check/run, AutoCheck, nonce extraction,
    # option handling and JSON construction execute. This does not prove a
    # target account's role or authentication; those require the genuine lab.
    it 'uses wp_capabilities when DB_PREFIX is left at its default' do
      expect(fields).to eq('wp_capabilities' => { 'value' => { 'administrator' => 1 } })
    end

    it 'preserves the registration endpoint and captured nonce' do
      fields

      expect(requests.last).to include(
        'method' => 'POST',
        'uri' => '/wp-admin/admin-ajax.php',
        'ctype' => 'application/json',
        'vars_get' => { 'action' => 'stm_lms_register', 'nonce' => '13259520e4' }
      )
    end

    context 'when DB_PREFIX is lab_' do
      before { mod.datastore['DB_PREFIX'] = 'lab_' }

      it 'uses only lab_capabilities for the administrator field' do
        expect(fields).to eq('lab_capabilities' => { 'value' => { 'administrator' => 1 } })
      end

      it 'preserves the supplied prefix in the datastore' do
        fields

        expect(mod.datastore['DB_PREFIX']).to eq('lab_')
      end
    end

    context 'when DB_PREFIX is empty' do
      before { mod.datastore['DB_PREFIX'] = '' }

      it 'uses the unprefixed capabilities key' do
        expect(fields).to eq('capabilities' => { 'value' => { 'administrator' => 1 } })
      end
    end
  end
end
