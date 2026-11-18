require 'rspec'
require 'json'
require 'tempfile'
require 'msfenv'
require 'msf/base'

RSpec.describe 'MySQL Directory Write Test' do
  subject(:mod) do
    source = File.expand_path('../../../../../modules/auxiliary/scanner/mysql/mysql_writable_dirs.rb', __dir__)
    scope = Module.new
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap do |klass|
      klass.include(Msf)
      klass.framework = framework
    end.new
  end

  let(:framework) { double('framework', features: double('features', enabled?: true), datastore: Msf::DataStore.new) }
  let(:client) { double('MySQL client', peerhost: '192.0.2.53', peerport: 3306) }
  let(:directory) { '/var/lib/mysql-files/module-write/ordinary' }
  let(:filename) { 'module-write-test.txt' }
  let(:sql_mode) { capture.fetch('sql_modes').fetch('default') }
  let(:write_error) { nil }
  let(:queries) { [] }
  let(:capture) do
    JSON.parse(File.read(File.expand_path('../../../../file_fixtures/modules/auxiliary/mysql_write_dirs_8_0_36.json', __dir__)))
  end
  let(:directory_list) do
    Tempfile.new('mysql-write-directories-spec').tap do |file|
      file.write(directory + "\n")
      file.flush
    end
  end

  # Query adapters are synthetic; error messages and path outcomes are captures.
  before do
    mod.datastore['RHOST'] = '192.0.2.53'
    mod.datastore['DIR_LIST'] = directory_list.path
    mod.datastore['FILE_NAME'] = filename
    mod.mysql_conn = client
    allow(mod).to receive(:session).and_return(nil)
    allow(mod).to receive(:mysql_login_datastore).and_return(true)
    allow(mod).to receive(:report_note)
    allow(mod).to receive(:print_good)
    allow(mod).to receive(:print_warning)
    allow(client).to receive(:query) do |query|
      queries << query
      case query
      when 'SELECT @@SESSION.sql_mode'
        [[sql_mode]]
      when /\ASELECT _utf8'test' INTO DUMPFILE /
        raise write_error if write_error

        nil
      else
        raise ArgumentError, 'Unexpected synthetic query: ' + query
      end
    end
  end

  after { directory_list.close! }

  it 'retains the existing successful note shape' do
    mod.run_host('192.0.2.53')

    expect(mod).to have_received(:report_note).with(hash_including(type: 'filesystem.file', data: { dir: directory, permissions: 'writeable' }))
  end

  context 'with a space in the directory' do
    let(:directory) { '/var/lib/mysql-files/module-write/space dir' }

    it 'preserves the complete ordinary pathname' do
      mod.run_host('192.0.2.53')

      expect(queries).to include("SELECT _utf8'test' INTO DUMPFILE '/var/lib/mysql-files/module-write/space dir/module-write-test.txt'")
    end
  end

  context 'with a quote in the filename' do
    let(:filename) { captured_filename('quoted-filename') }

    it 'escapes the filename as part of one complete path literal' do
      mod.run_host('192.0.2.53')

      expect(queries).to include("SELECT _utf8'test' INTO DUMPFILE '/var/lib/mysql-files/module-write/ordinary/module-write\\'quote.txt'")
    end
  end

  context 'with a quote in the directory' do
    let(:directory) { captured_directory('quoted-directory') }

    it 'escapes the directory in the same path literal' do
      mod.run_host('192.0.2.53')

      expect(queries).to include("SELECT _utf8'test' INTO DUMPFILE '/var/lib/mysql-files/module-write/quote\\'dir/module-write-test.txt'")
    end
  end

  context 'with a backslash in the filename' do
    let(:filename) { captured_filename('backslash-filename') }

    it 'prevents the captured conversion of backslash b into a backspace byte' do
      mod.run_host('192.0.2.53')

      expect(queries).to include("SELECT _utf8'test' INTO DUMPFILE '/var/lib/mysql-files/module-write/ordinary/module-write\\\\back.txt'")
    end
  end

  context 'with a backslash in the directory' do
    let(:directory) { captured_directory('backslash-directory') }

    it 'does not discard the literal directory backslash' do
      mod.run_host('192.0.2.53')

      expect(queries).to include("SELECT _utf8'test' INTO DUMPFILE '/var/lib/mysql-files/module-write/back\\\\slash-dir/module-write-test.txt'")
    end
  end

  context 'with both special characters in one filename' do
    let(:filename) { captured_filename('backslash-quote-filename') }

    it 'quotes both without changing the intended path' do
      mod.run_host('192.0.2.53')

      expect(queries).to include("SELECT _utf8'test' INTO DUMPFILE '/var/lib/mysql-files/module-write/ordinary/module-write\\\\back\\'quote.txt'")
    end
  end

  context 'with NO_BACKSLASH_ESCAPES' do
    let(:sql_mode) { capture.fetch('sql_modes').fetch('no_backslash_escapes') }

    context 'with a quote in the filename' do
      let(:filename) { "module-write'quote.txt" }

      it 'uses quote doubling rather than inactive backslash escaping' do
        mod.run_host('192.0.2.53')

        expect(queries).to include("SELECT _utf8'test' INTO DUMPFILE '/var/lib/mysql-files/module-write/ordinary/module-write''quote.txt'")
      end
    end

    context 'with a backslash in the filename' do
      let(:filename) { 'module-write\back.txt' }

      it 'retains an already literal backslash' do
        mod.run_host('192.0.2.53')

        expect(queries).to include("SELECT _utf8'test' INTO DUMPFILE '/var/lib/mysql-files/module-write/ordinary/module-write\\back.txt'")
      end
    end

    context 'with both special characters' do
      let(:filename) { "module-write\\back'quote.txt" }

      it 'doubles the quote while retaining the backslash' do
        mod.run_host('192.0.2.53')

        expect(queries).to include("SELECT _utf8'test' INTO DUMPFILE '/var/lib/mysql-files/module-write/ordinary/module-write\\back''quote.txt'")
      end
    end
  end

  shared_examples 'a rejected write' do |label|
    let(:write_error) { captured_error(label) }

    it 'retains the server reason and creates no writable note' do
      mod.run_host('192.0.2.53')

      expect(mod).to have_received(:print_warning).with(write_error.message)
      expect(mod).not_to have_received(:report_note)
    end
  end

  context 'with an existing file' do
    include_examples 'a rejected write', 'collision'
  end

  context 'without SQL FILE permission' do
    include_examples 'a rejected write', 'file-permission'
  end

  it 'does not query or report after authentication fails' do
    allow(mod).to receive(:mysql_login_datastore).and_return(false)
    mod.run_host('192.0.2.53')

    expect(queries).to eq([])
    expect(mod).not_to have_received(:report_note)
  end

  it 'uses the borrowed client without changing session SQL mode or database' do
    allow(mod).to receive(:session).and_return(double('MySQL session', sid: 7, client: client, type: 'mysql'))
    mod.run_host('192.0.2.53')

    expect(mod).not_to have_received(:mysql_login_datastore)
    expect(queries.grep(/\A(?:SET|USE) /)).to eq([])
    expect(mod).to have_received(:report_note)
  end

  it 'stops with an operation reason if the current SQL mode cannot be read' do
    allow(client).to receive(:query).with('SELECT @@SESSION.sql_mode').and_return(nil)

    expect { mod.run_host('192.0.2.53') }.to raise_error(Msf::Auxiliary::Scanner::AttemptFailed, 'unexpected-reply: Unable to determine the MySQL session SQL mode')
    expect(queries.grep(/\ASELECT _utf8'test' INTO DUMPFILE /)).to eq([])
    expect(mod).not_to have_received(:report_note)
  end

  it 'reads a fresh mode before each run rather than keeping a stale quoting decision' do
    mod.datastore['FILE_NAME'] = "module-write'quote.txt"
    allow(client).to receive(:query).with('SELECT @@SESSION.sql_mode').and_return([[sql_mode]], [[capture.fetch('sql_modes').fetch('no_backslash_escapes')]])
    mod.run_host('192.0.2.53')
    mod.run_host('192.0.2.53')

    expect(queries.grep(/\ASELECT _utf8'test' INTO DUMPFILE /)).to eq([
      "SELECT _utf8'test' INTO DUMPFILE '/var/lib/mysql-files/module-write/ordinary/module-write\\'quote.txt'",
      "SELECT _utf8'test' INTO DUMPFILE '/var/lib/mysql-files/module-write/ordinary/module-write''quote.txt'"
    ])
  end

  it 'keeps direct check_dir calls compatible while reading the current connection mode' do
    mod.check_dir(directory)

    expect(queries).to include('SELECT @@SESSION.sql_mode')
    expect(mod).to have_received(:report_note)
  end

  def captured_error(label)
    row = capture.fetch('errors').find { |error| error.fetch('label') == label }
    klass = ::Mysql::ServerError::ERROR_MAP.fetch(row.fetch('code'), ::Mysql::ServerError)
    klass.new(row.fetch('message'), 'HY000', row.fetch('code'))
  end

  def captured_filename(label)
    row = capture.fetch('module_outcomes').find { |entry| entry.fetch('label') == label }
    [row.fetch('filename_hex')].pack('H*')
  end

  def captured_directory(label)
    row = capture.fetch('module_outcomes').find { |entry| entry.fetch('label') == label }
    [row.fetch('directories_hex').first].pack('H*')
  end
end
