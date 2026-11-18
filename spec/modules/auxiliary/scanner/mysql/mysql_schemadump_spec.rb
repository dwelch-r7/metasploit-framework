require 'rspec'
require 'json'
require 'msfenv'
require 'msf/base'

RSpec.describe 'MySQL Schema Dump' do
  subject(:mod) do
    source = File.expand_path('../../../../../modules/auxiliary/scanner/mysql/mysql_schemadump.rb', __dir__)
    scope = Module.new
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap do |klass|
      klass.include(Msf)
      klass.framework = framework
    end.new
  end

  let(:framework) { double('framework', features: double('features', enabled?: true), datastore: Msf::DataStore.new) }

  # Independent native catalog capture; query failures below are synthetic controls.
  let(:capture) do
    JSON.parse(File.read(File.expand_path('../../../../file_fixtures/modules/auxiliary/mysql_schema_8_0_36.json', __dir__)))
  end
  let(:query_results) do
    {
      'show databases' => capture.fetch('databases').map { |name| [name] },
      'SHOW tables from `module_basic`' => table_rows('module_basic'),
      'SHOW tables from `module_empty`' => [],
      'SHOW tables from `module odd-db`' => table_rows('module odd-db'),
      'SHOW tables from `module``quoted`' => table_rows('module`quoted'),
      'desc `module_basic`.`normal_rows`' => column_rows('module_basic', 'normal_rows'),
      'desc `module_basic`.`empty_rows`' => column_rows('module_basic', 'empty_rows'),
      'desc `module_basic`.`summary_view`' => column_rows('module_basic', 'summary_view'),
      'desc `module odd-db`.`order details`' => column_rows('module odd-db', 'order details'),
      'desc `module odd-db`.`select`' => column_rows('module odd-db', 'select'),
      'desc `module``quoted`.`table``quoted`' => column_rows('module`quoted', 'table`quoted')
    }
  end

  before do
    mod.datastore['RHOST'] = '192.0.2.53'
    allow(mod).to receive(:mysql_query) { |query| query_results.fetch(query) }
  end

  describe '#get_tbl_names' do
    it 'quotes ordinary database names' do
      expect(mod.get_tbl_names('module_basic')).to eq(capture.fetch('tables').fetch('module_basic'))
    end

    it 'quotes database names containing spaces and punctuation' do
      expect(mod.get_tbl_names('module odd-db')).to eq(['order details', 'select'])
    end

    it 'doubles embedded backticks inside the quoted database identifier' do
      expect(mod.get_tbl_names('module`quoted')).to eq(['table`quoted'])
    end

    it 'preserves an empty table list' do
      expect(mod.get_tbl_names('module_empty')).to eq([])
    end
  end

  describe '#get_columns' do
    it 'quotes the database and table separately when names contain spaces' do
      expect(mod.get_columns('module odd-db', 'order details')).to eq([
        ['first column', 'int'], ['text-value', 'varchar(11)']
      ])
    end

    it 'quotes a reserved table name' do
      expect(mod.get_columns('module odd-db', 'select')).to eq([['from', 'smallint']])
    end

    it 'doubles embedded backticks in both identifier components' do
      expect(mod.get_columns('module`quoted', 'table`quoted')).to eq([
        ['column`quoted', 'varchar(9)'], ['normal_column', 'bigint']
      ])
    end
  end

  describe '#get_schema' do
    it 'retains the native database, table and ordered column metadata' do
      expected = capture.fetch('databases').map do |database|
        {
          'DBName' => database,
          'Tables' => capture.fetch('tables').fetch(database).map do |table|
            {
              'TableName' => table,
              'Columns' => column_rows(database, table).map { |name, type| { 'ColumnName' => name, 'ColumnType' => type } }
            }
          end
        }
      end

      expect(mod.get_schema).to eq(expected)
    end

    it 'retains an empty result for an account with no visible application databases' do
      query_results['show databases'] = [['information_schema']]

      expect(mod.get_schema).to eq([])
    end
  end

  describe '#run_host query failures' do
    before do
      allow(mod).to receive(:session).and_return(nil)
      allow(mod).to receive(:mysql_login_datastore).and_return(true)
      allow(mod).to receive(:report_note)
      allow(mod).to receive(:report_service)
      allow(mod).to receive(:store_loot)
    end

    shared_examples 'an aborted schema dump' do |query, message|
      it 'reports the failed query operation before writing any schema evidence' do
        query_results[query] = nil

        expect { mod.run_host('192.0.2.53') }.to raise_error(Msf::Auxiliary::Scanner::AttemptFailed, "unexpected-reply: #{message}")
        expect(mod).not_to have_received(:report_note)
        expect(mod).not_to have_received(:report_service)
        expect(mod).not_to have_received(:store_loot)
      end
    end

    context 'when listing databases fails' do
      include_examples 'an aborted schema dump', 'show databases', 'Unable to enumerate MySQL databases'
    end

    context 'when listing tables fails' do
      include_examples 'an aborted schema dump', 'SHOW tables from `module_basic`', 'Unable to enumerate tables in database module_basic'
    end

    context 'when describing columns fails' do
      include_examples 'an aborted schema dump', 'desc `module_basic`.`normal_rows`', 'Unable to enumerate columns in table module_basic.normal_rows'
    end
  end

  describe '#run_host reporting' do
    let(:service) { double('named MySQL service') }
    let(:schema) { { 'DBName' => 'module_empty', 'Tables' => [] } }

    before do
      allow(mod).to receive(:session).and_return(nil)
      allow(mod).to receive(:mysql_login_datastore).and_return(true)
      allow(mod).to receive(:mysql_conn).and_return(double('MySQL client', peerhost: '192.0.2.53', peerport: 3306))
      allow(mod).to receive(:get_schema).and_return([schema])
      allow(mod).to receive(:report_service).and_return(service)
      allow(mod).to receive(:report_note)
      allow(mod).to receive(:store_loot).and_return('/tmp/mysql-schema.txt')
      allow(mod).to receive(:print_good)
    end

    it 'anchors schema notes to the exact named service without an ambiguous port lookup' do
      mod.run_host('192.0.2.53')

      expect(mod).to have_received(:report_note).with(
        host: '192.0.2.53',
        service: service,
        type: 'mysql.db.schema',
        data: { database: schema },
        update: :unique_data
      )
    end
  end

  def table_rows(database)
    capture.fetch('tables').fetch(database).map { |name| [name] }
  end

  def column_rows(database, table)
    capture.fetch('columns').fetch(database).fetch(table)
  end
end
