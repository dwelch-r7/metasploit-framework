require 'msfenv'
require 'msf/base'
require 'rex/text'
require 'csv'

RSpec.describe '.netrc credential collection' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = File.expand_path('../../../../../modules/post/multi/gather/netrc_creds.rb', __dir__)
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:framework) { double('Framework', datastore: Msf::DataStore.new) }
  let(:session) { double('Command shell session') }
  let(:target) { '/root/.netrc' }
  let(:fixtures) { File.expand_path('../../../../file_fixtures/modules/post/multi/gather/netrc_creds', __dir__) }
  let(:fixture_name) { 'multiline.netrc' }
  let(:netrc_data) { File.binread(File.join(fixtures, fixture_name)) }
  let(:native_csv) { File.binread(File.join(fixtures, 'multiline.csv')) }
  let(:stored_loot) { [] }
  let(:reported_csv) { stored_loot.map { |loot| loot.fetch(3) } }

  # These files were consumed by Ubuntu curl 7.81.0 on 2026-11-17. Its native
  # authenticated HTTP controls accepted each syntax fixture and rejected the
  # wrong password. The CSV is an exact capture from the original owner using
  # a genuine root shell and PostgreSQL loot reporting for multiline.netrc.
  # Transport, framework access, persistence and output are doubled here; the
  # owner parsing, Rex table and CSV generation run without parser/result stubs.
  before do
    allow(mod).to receive_messages(framework: framework, session: session)
    allow(mod).to receive(:enum_user_directories).and_return(['/root'])
    allow(mod).to receive(:readable?).and_return(false)
    allow(mod).to receive(:readable?).with(target).and_return(true)
    allow(mod).to receive(:read_file).with(target).and_return(netrc_data)
    allow(mod).to receive(:store_loot) do |*args|
      stored_loot << args
      '/loot/netrc_credentials.txt'
    end
    allow(mod).to receive(:print_status)
    allow(mod).to receive(:vprint_error)
    allow(mod).to receive(:print_line)
  end

  it 'preserves the exact captured multiline CSV' do
    mod.run

    expect(reported_csv).to eq([native_csv])
  end

  it 'preserves the loot reporting contract without creating credential cores' do
    expect(mod).not_to receive(:create_credential)

    mod.run

    expect(mod).to have_received(:store_loot).with('netrc.creds', 'text/csv', session, native_csv, 'netrc_credentials.txt', '.netrc credentials')
  end

  context 'with the captured inline file' do
    let(:fixture_name) { 'inline.netrc' }

    it 'collects the same credential' do
      mod.run

      expect(reported_csv).to eq([native_csv])
    end
  end

  context 'with the captured tab-separated file' do
    let(:fixture_name) { 'tabs.netrc' }

    it 'collects the credential accepted by the native client' do
      mod.run

      expect(reported_csv).to eq([native_csv])
    end
  end

  context 'with the captured commented file' do
    let(:fixture_name) { 'comments.netrc' }

    it 'excludes the commented credential from CSV loot' do
      mod.run

      expect(reported_csv).to eq([native_csv])
    end
  end

  context 'with the captured multiple-machine file' do
    let(:fixture_name) { 'multiple.netrc' }

    it 'retains both machines as separate CSV rows' do
      mod.run

      expect(stored_loot.map { |loot| CSV.parse(loot.fetch(3)) }).to eq([
        [
          ['Username', 'Password', 'Server'],
          ['module-test-user', 'module-test-password', 'netrc-auth'],
          ['module-test-user', 'module-test-password', 'netrc-alias']
        ]
      ])
    end
  end

  context 'with the captured rejected password file' do
    let(:fixture_name) { 'wrong.netrc' }

    it 'collects the stored password without claiming it is valid' do
      mod.run

      expect(stored_loot.map { |loot| CSV.parse(loot.fetch(3)) }).to eq([
        [
          ['Username', 'Password', 'Server'],
          ['module-test-user', 'module-target-wrong-password', 'netrc-auth']
        ]
      ])
    end
  end

  it 'does not read or collect an unreadable file' do
    allow(mod).to receive(:readable?).with(target).and_return(false)
    expect(mod).not_to receive(:read_file)

    mod.run

    expect(stored_loot).to be_empty
  end

  it 'does not store loot for an empty file' do
    allow(mod).to receive(:read_file).with(target).and_return('')

    mod.run

    expect(stored_loot).to be_empty
  end

  it 'does not store loot for an incomplete final entry' do
    allow(mod).to receive(:read_file).with(target).and_return("machine netrc-auth\nlogin module-test-user\n")

    mod.run

    expect(stored_loot).to be_empty
  end

  it 'continues to another user when a previously readable file returns nil' do
    # Transport boundary case; the native baseline did not reproduce this race.
    allow(mod).to receive(:enum_user_directories).and_return(['/root', '/home/lab user'])
    allow(mod).to receive(:readable?).with('/home/lab user/.netrc').and_return(true)
    allow(mod).to receive(:read_file).with(target).and_return(nil)
    expect(mod).to receive(:read_file).with('/home/lab user/.netrc').and_return(netrc_data)

    mod.run

    expect(reported_csv).to eq([native_csv])
  end

  it 'does not carry credentials from an earlier execution into an empty one' do
    allow(mod).to receive(:read_file).with(target).and_return(netrc_data, '')

    mod.run
    mod.run

    expect(reported_csv).to eq([native_csv])
  end

  it 'rereads and reports the file on a second execution' do
    expect(mod).to receive(:read_file).with(target).twice.and_return(netrc_data)

    mod.run
    mod.run

    expect(reported_csv).to eq([native_csv, native_csv])
  end
end
