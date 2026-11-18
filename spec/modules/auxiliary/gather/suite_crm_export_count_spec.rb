require 'rspec'
require 'msfenv'
require 'msf/base'

RSpec.describe 'SuiteCRM export user count' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    source = File.expand_path('../../../../modules/auxiliary/gather/suite_crm_export_sqli.rb', __dir__)
    scope = Module.new
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap do |klass|
      klass.include(Msf)
      klass.framework = framework
    end
  end
  let(:framework) { double('framework', datastore: Msf::DataStore.new) }
  let(:sqli) { double('synthetic comma-free SQL transport') }
  let(:queries) { [] }
  let(:usernames) { %w[charlie alpha delta bravo alpha] }

  before do
    allow(mod).to receive(:print_status)
    allow(mod).to receive(:print_warning)
    allow(mod).to receive(:print_line)
    # This bounded query adapter is synthetic. Native SQL, HTTP and credential
    # evidence comes from the separate real SuiteCRM target replay.
    allow(sqli).to receive(:run_sql) do |sql|
      queries << sql
      query = sql.downcase.gsub(/\s+/, ' ')
      if query == 'select group_concat(distinct user_name) from users'
        usernames.uniq.sort.join(',')
      elsif (match = query.match(/\Aselect group_concat\(user_name order by user_name\) from \(select distinct user_name from users order by user_name(?: limit (\d+))?\) suitecrm_users\z/))
        selected = usernames.uniq.sort
        selected = selected.first(match[1].to_i) if match[1]
        selected.join(',')
      else
        raise ArgumentError, 'Unexpected synthetic query: ' + sql
      end
    end
  end

  it 'uses the existing default limit of three distinct users' do
    expect(mod.get_user_names(sqli)).to eq(%w[alpha bravo charlie])
  end

  it 'limits COUNT=1 before aggregating usernames' do
    mod.datastore['COUNT'] = 1

    expect(mod.get_user_names(sqli)).to eq(['alpha'])
  end

  it 'selects a deterministic distinct pair for COUNT=2' do
    mod.datastore['COUNT'] = 2

    expect(mod.get_user_names(sqli)).to eq(%w[alpha bravo])
  end

  it 'returns the available users when COUNT exceeds the row count' do
    mod.datastore['COUNT'] = 10

    expect(mod.get_user_names(sqli)).to eq(%w[alpha bravo charlie delta])
  end

  it 'keeps COUNT=0 as an explicit request for all users' do
    mod.datastore['COUNT'] = 0

    expect(mod.get_user_names(sqli)).to eq(%w[alpha bravo charlie delta])
  end

  it 'keeps an unset optional COUNT unbounded for direct callers' do
    allow(mod.datastore).to receive(:[]).and_call_original
    allow(mod.datastore).to receive(:[]).with('COUNT').and_return(nil)

    expect(mod.get_user_names(sqli)).to eq(%w[alpha bravo charlie delta])
  end

  it 'does not encode a zero LIMIT for an unbounded request' do
    mod.datastore['COUNT'] = 0
    mod.get_user_names(sqli)

    expect(queries.last).not_to match(/\blimit\b/i)
  end

  it 'preserves the transport constraint that SQL cannot contain a comma' do
    mod.datastore['COUNT'] = 1
    mod.get_user_names(sqli)

    expect(queries.last).not_to include(',')
  end

  it 'rejects a negative COUNT with an actionable configuration reason' do
    mod.datastore['COUNT'] = -1

    expect { mod.get_user_names(sqli) }.to raise_error(Msf::Auxiliary::Failed, /COUNT must be zero or greater/)
  end

  it 'does not send an extraction query for a negative COUNT' do
    mod.datastore['COUNT'] = -1
    begin
      mod.get_user_names(sqli)
    rescue Msf::Auxiliary::Failed
      nil
    end

    expect(queries).to eq([])
  end

  it 'rejects a noninteger from a direct datastore adapter' do
    allow(mod.datastore).to receive(:[]).and_call_original
    allow(mod.datastore).to receive(:[]).with('COUNT').and_return('unbounded')

    expect { mod.get_user_names(sqli) }.to raise_error(Msf::Auxiliary::Failed, /COUNT must be zero or greater/)
  end

  it 'rejects a fractional value from a direct datastore adapter' do
    allow(mod.datastore).to receive(:[]).and_call_original
    allow(mod.datastore).to receive(:[]).with('COUNT').and_return(1.5)

    expect { mod.get_user_names(sqli) }.to raise_error(Msf::Auxiliary::Failed, /COUNT must be zero or greater/)
  end

  it 'reads the configured limit again on a later invocation' do
    mod.datastore['COUNT'] = 1
    first = mod.get_user_names(sqli)
    mod.datastore['COUNT'] = 2
    second = mod.get_user_names(sqli)

    expect([first, second]).to eq([['alpha'], %w[alpha bravo]])
  end

  context 'with no returned usernames' do
    let(:usernames) { [] }

    it 'preserves an empty array return' do
      expect(mod.get_user_names(sqli)).to eq([])
    end
  end

  it 'passes only selected users to hash collection from run' do
    mod.datastore['AutoCheck'] = false
    mod.datastore['COUNT'] = 1
    allow(mod).to receive(:authenticate).and_return(true)
    allow(mod).to receive(:init_sqli).and_return(sqli)
    allow(mod).to receive(:get_user_hashes).and_return([])
    mod.run

    expect(mod).to have_received(:get_user_hashes).with(sqli, ['alpha'])
  end
end
