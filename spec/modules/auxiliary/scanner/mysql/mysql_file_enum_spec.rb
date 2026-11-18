require 'rspec'
require 'json'
require 'tempfile'
require 'msfenv'
require 'msf/base'

RSpec.describe 'MySQL File/Directory Enumerator' do
  subject(:mod) do
    source = File.expand_path('../../../../../modules/auxiliary/scanner/mysql/mysql_file_enum.rb', __dir__)
    scope = Module.new
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap do |klass|
      klass.include(Msf)
      klass.framework = framework
    end.new
  end

  let(:framework) { double('framework', features: double('features', enabled?: true), datastore: Msf::DataStore.new) }
  let(:client) { double('MySQL client', peerhost: '192.0.2.53', peerport: 3306) }
  let(:path) { '/var/lib/mysql-files/module-target/numbers.txt' }
  let(:sql_mode) { 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION' }
  let(:table_exists) { false }
  let(:load_error) { nil }
  let(:queries) { [] }
  let(:capture) do
    JSON.parse(File.read(File.expand_path('../../../../file_fixtures/modules/auxiliary/mysql_file_enum_8_0_36.json', __dir__)))
  end
  let(:file_list) do
    Tempfile.new('mysql-file-enum-spec').tap do |file|
      file.write(path + "\n")
      file.flush
    end
  end

  # Query results are synthetic adapters; server error messages/codes are captures.
  before do
    mod.datastore['RHOST'] = '192.0.2.53'
    mod.datastore['DATABASE_NAME'] = 'module_files'
    mod.datastore['TABLE_NAME'] = 'module_enum_probe'
    mod.datastore['FILE_LIST'] = file_list.path
    mod.mysql_conn = client
    allow(mod).to receive(:session).and_return(nil)
    allow(mod).to receive(:mysql_login_datastore).and_return(true)
    allow(mod).to receive(:report_note)
    allow(mod).to receive(:print_good)
    allow(mod).to receive(:vprint_warning)
    allow(client).to receive(:escape_string) { |value| ::Mysql.escape_string(value) }
    allow(client).to receive(:query) do |query|
      queries << query
      case query
      when 'SELECT @@SESSION.sql_mode'
        [[sql_mode]]
      when /\ASELECT \* FROM information_schema.TABLES /
        table_exists ? [['present']] : []
      when /\ALOAD DATA INFILE /
        raise load_error if load_error

        nil
      when /\A(?:USE |CREATE TABLE |DROP TABLE )/
        nil
      else
        raise ArgumentError, 'Unexpected synthetic query: ' + query
      end
    end
  end

  after { file_list.close! }

  describe 'identifier and file-name quoting' do
    it 'quotes the database selected by the operator' do
      mod.datastore['DATABASE_NAME'] = 'module files'
      mod.run_host('192.0.2.53')

      expect(queries).to include('USE `module files`')
    end

    it 'quotes a temporary table for creation, load and removal' do
      mod.datastore['TABLE_NAME'] = 'module`enum table'
      mod.run_host('192.0.2.53')

      expect(queries).to include('CREATE TABLE `module``enum table` (brute int);', "LOAD DATA INFILE '#{path}' INTO TABLE `module``enum table`", 'DROP TABLE `module``enum table`')
    end

    context 'when a file name contains a single quote' do
      let(:path) { "/var/lib/mysql-files/module-target/quote'file.txt" }

      it 'uses the existing client escaping API with ordinary SQL modes' do
        mod.run_host('192.0.2.53')

        expect(queries).to include("LOAD DATA INFILE '/var/lib/mysql-files/module-target/quote\\'file.txt' INTO TABLE `module_enum_probe`")
      end

      context 'with NO_BACKSLASH_ESCAPES' do
        let(:sql_mode) { 'STRICT_TRANS_TABLES,NO_BACKSLASH_ESCAPES' }

        it 'doubles quotes instead of adding an inactive backslash escape' do
          mod.run_host('192.0.2.53')

          expect(queries).to include("LOAD DATA INFILE '/var/lib/mysql-files/module-target/quote''file.txt' INTO TABLE `module_enum_probe`")
        end
      end
    end
  end

  describe 'captured server outcomes' do
    shared_examples 'a discovered file' do |label|
      let(:load_error) { captured_error(label) }

      it 'stores a file field rather than a directory field' do
        mod.run_host('192.0.2.53')

        expect(mod).to have_received(:report_note).with(hash_including(type: 'filesystem.file', data: { file: path }))
      end
    end

    context 'when the file contains nonnumeric text' do
      include_examples 'a discovered file', 'load-text'
    end

    context 'when an integer value is out of range' do
      include_examples 'a discovered file', 'load-range'
    end

    context 'when native LOAD DATA succeeds' do
      it 'retains the existing file report shape' do
        mod.run_host('192.0.2.53')

        expect(mod).to have_received(:report_note).with(hash_including(type: 'filesystem.file', data: { file: path }))
      end
    end

    context 'when the native server rejects a directory' do
      let(:load_error) { captured_error('load-directory') }

      it 'retains the existing directory report shape' do
        mod.run_host('192.0.2.53')

        expect(mod).to have_received(:report_note).with(hash_including(type: 'filesystem.dir', data: { directory: path }))
      end
    end

    shared_examples 'an indeterminate path' do |label|
      let(:load_error) { captured_error(label) }

      it 'preserves the native failure rather than claiming that the path is absent' do
        mod.run_host('192.0.2.53')

        expect(mod).to have_received(:vprint_warning).with(include(path, load_error.message))
        expect(mod).not_to have_received(:vprint_warning).with(include(path + ' does not exist'))
        expect(mod).not_to have_received(:report_note)
      end
    end

    context 'when filesystem permissions deny reading' do
      include_examples 'an indeterminate path', 'load-private'
    end

    context 'when SQL FILE permission is absent' do
      include_examples 'an indeterminate path', 'load-denied'
    end

    context 'when the server cannot stat the file' do
      include_examples 'an indeterminate path', 'load-missing'
    end
  end

  describe 'repeat state' do
    it 'refreshes the real connection SQL mode before each run' do
      mod.run_host('192.0.2.53')
      mod.run_host('192.0.2.53')

      expect(queries.count('SELECT @@SESSION.sql_mode')).to eq(2)
    end

    context 'when the connection SQL mode changes between runs' do
      let(:path) { "/var/lib/mysql-files/module-target/quote'file.txt" }

      it 'uses the newly observed mode instead of a stale escaping decision' do
        allow(client).to receive(:query).with('SELECT @@SESSION.sql_mode').and_return([[sql_mode]], [['NO_BACKSLASH_ESCAPES']])
        mod.run_host('192.0.2.53')
        mod.run_host('192.0.2.53')

        expect(queries.grep(/\ALOAD DATA INFILE /)).to eq([
          "LOAD DATA INFILE '/var/lib/mysql-files/module-target/quote\\'file.txt' INTO TABLE `module_enum_probe`",
          "LOAD DATA INFILE '/var/lib/mysql-files/module-target/quote''file.txt' INTO TABLE `module_enum_probe`"
        ])
      end
    end

    context 'with an existing table' do
      let(:table_exists) { true }

      it 'keeps the existing table rather than creating or dropping it' do
        mod.run_host('192.0.2.53')

        expect(queries.grep(/\A(?:CREATE|DROP) TABLE /)).to eq([])
      end
    end
  end

  describe 'failed query returns' do
    before { allow(mod).to receive(:mysql_query).and_call_original }

    it 'stops when the session SQL mode cannot be obtained' do
      allow(mod).to receive(:mysql_query).with('SELECT @@SESSION.sql_mode').and_return(nil)

      expect { mod.run_host('192.0.2.53') }.to raise_error(Msf::Auxiliary::Scanner::AttemptFailed, 'unexpected-reply: Unable to determine the MySQL session SQL mode')
      expect(queries.grep(/\A(?:CREATE TABLE|LOAD DATA) /)).to eq([])
      expect(mod).not_to have_received(:report_note)
    end

    it 'stops when temporary-table discovery cannot be obtained' do
      allow(mod).to receive(:mysql_query).with(a_string_starting_with('SELECT * FROM information_schema.TABLES ')).and_return(nil)

      expect { mod.run_host('192.0.2.53') }.to raise_error(Msf::Auxiliary::Scanner::AttemptFailed, 'unexpected-reply: Unable to inspect the MySQL enumeration table')
      expect(queries.grep(/\A(?:CREATE TABLE|LOAD DATA) /)).to eq([])
      expect(mod).not_to have_received(:report_note)
    end
  end

  def captured_error(label)
    row = capture.fetch('errors').find { |error| error.fetch('label') == label }
    klass = ::Mysql::ServerError::ERROR_MAP.fetch(row.fetch('code'), ::Mysql::ServerError)
    klass.new(row.fetch('message'), 'HY000', row.fetch('code'))
  end
end
