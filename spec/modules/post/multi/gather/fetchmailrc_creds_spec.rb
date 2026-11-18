require 'msfenv'
require 'msf/base'
require 'rex/text'
require 'csv'

RSpec.describe 'Fetchmail credential collection' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = File.expand_path('../../../../../modules/post/multi/gather/fetchmailrc_creds.rb', __dir__)
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:framework) { double('Framework', datastore: Msf::DataStore.new) }
  let(:session) { double('Command shell session') }
  let(:target) { '/root/.fetchmailrc' }
  let(:fixtures) { File.expand_path('../../../../file_fixtures/modules/post/multi/gather/fetchmailrc_creds', __dir__) }
  let(:fixture_name) { 'plain.fetchmailrc' }
  let(:file_data) { File.binread(File.join(fixtures, fixture_name)) }
  let(:native_csv) { File.binread(File.join(fixtures, 'plain.csv')) }
  let(:catalogue) { JSON.parse(File.binread(File.join(fixtures, 'catalogue.json'))) }
  let(:stored_loot) { [] }
  let(:reported_csv) { stored_loot.map { |loot| loot.fetch(3) } }
  let(:ordinary_line) { 'poll localhost protocol POP3 port 110 user module_target password module-target-password' }

  # Eight exact files were accepted by Fetchmail 6.4.27 with Dovecot 2.3.16 on
  # 2026-11-18. The plain CSV is captured from a genuine original-owner shell
  # and PostgreSQL loot report. Transport, framework access, persistence and
  # output are doubled; owner parsing/defaults, Rex tables and CSV are real.
  before do
    allow(mod).to receive_messages(framework: framework, session: session)
    allow(mod).to receive(:enum_user_directories).and_return(['/root'])
    allow(mod).to receive(:readable?).and_return(false)
    allow(mod).to receive(:readable?).with(target).and_return(true)
    allow(mod).to receive(:read_file).with(target).and_return(file_data)
    allow(mod).to receive(:store_loot) do |*args|
      stored_loot << args
      '/loot/fetchmailrc_credentials.txt'
    end
    allow(mod).to receive(:print_status)
    allow(mod).to receive(:vprint_error)
    allow(mod).to receive(:print_error)
    allow(mod).to receive(:print_line)
  end

  shared_examples 'a native Fetchmail file' do |file_name|
    let(:fixture_name) { file_name }

    it "collects the exact #{file_name} accounts" do
      expected = [CSV.parse(native_csv).first] + catalogue.fetch(file_name).fetch('accounts').map do |account|
        account.values_at('user', 'password', 'host', 'protocol', 'port')
      end

      mod.run

      expect(reported_csv.map { |data| CSV.parse(data) }).to eq([expected])
    end
  end

  it_behaves_like 'a native Fetchmail file', 'plain.fetchmailrc'
  it_behaves_like 'a native Fetchmail file', 'imap.fetchmailrc'
  it_behaves_like 'a native Fetchmail file', 'comments.fetchmailrc'
  it_behaves_like 'a native Fetchmail file', 'blanks.fetchmailrc'
  it_behaves_like 'a native Fetchmail file', 'multiline.fetchmailrc'
  it_behaves_like 'a native Fetchmail file', 'defaults.fetchmailrc'
  it_behaves_like 'a native Fetchmail file', 'quoted-password.fetchmailrc'
  it_behaves_like 'a native Fetchmail file', 'multiple-users.fetchmailrc'

  it 'preserves exact captured CSV and loot metadata without creating credential cores' do
    expect(mod).not_to receive(:create_credential)

    mod.run

    expect(mod).to have_received(:store_loot).with('fetchmailrc.creds', 'text/csv', session, native_csv, 'fetchmailrc_credentials.txt', '.fetchmailrc credentials')
  end

  describe '#parse_fetchmailrc_line' do
    it 'preserves unquoted aliases and via host selection' do
      line = 'poll alias via localhost proto POP3 service 110 username module_target pass module-target-password'

      expect(mod.parse_fetchmailrc_line(line)).to eq([
        { users: ['module_target'], passwords: ['module-target-password'], host: 'localhost', protocol: 'POP3', port: '110' }
      ])
    end

    context 'with source-derived quoted strings' do
      # The matching 6.4.27 rcfile_l.l STRING rules accept both quote styles.
      # These are parser boundaries, without native account/authentication claims.
      # https://archive.ubuntu.com/ubuntu/pool/main/f/fetchmail/fetchmail_6.4.27.orig.tar.xz
      it 'extracts a complete double-quoted username' do
        line = 'poll localhost protocol POP3 user "space user" password "module target password"'

        expect(mod.parse_fetchmailrc_line(line).first).to include(users: ['space user'], passwords: ['module target password'])
      end

      it 'extracts complete single-quoted credentials' do
        line = "poll localhost protocol POP3 user 'space user' password 'module target password'"

        expect(mod.parse_fetchmailrc_line(line).first).to include(users: ['space user'], passwords: ['module target password'])
      end

      it 'does not interpret user options inside a quoted password' do
        line = 'poll localhost protocol POP3 user module_target password "literal user other password tail"'

        expect(mod.parse_fetchmailrc_line(line).first).to include(users: ['module_target'], passwords: ['literal user other password tail'])
      end

      it 'does not interpret password options inside a quoted username' do
        line = 'poll localhost protocol POP3 user "literal password other" password secret'

        expect(mod.parse_fetchmailrc_line(line).first).to include(users: ['literal password other'], passwords: ['secret'])
      end

      it 'extracts quoted ESMTP credentials as a separate account' do
        line = ordinary_line + ' esmtpname "smtp user" esmtppassword "smtp password" smtphost smtp.example.test'

        expect(mod.parse_fetchmailrc_line(line).last).to eq(
          users: ['smtp user'], passwords: ['smtp password'], host: 'smtp.example.test', protocol: 'esmtp'
        )
      end
    end

    it 'preserves ordinary ESMTP account extraction' do
      line = ordinary_line + ' esmtpname smtp_user esmtppassword smtp_password smtphost smtp.example.test'

      expect(mod.parse_fetchmailrc_line(line).last).to eq(
        users: ['smtp_user'], passwords: ['smtp_password'], host: 'smtp.example.test', protocol: 'esmtp'
      )
    end

    it 'preserves existing literal escape bytes outside native qualification' do
      # Fetchmail's escapes() decodes these bytes; decoding remains outside
      # this quote-extraction repair. This assertion protects existing behavior.
      line = 'poll localhost protocol POP3 user module_target password "literal\tpassword"'

      expect(mod.parse_fetchmailrc_line(line).first).to include(passwords: ['literal\tpassword'])
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

  it 'preserves skipping mismatched user and password counts' do
    allow(mod).to receive(:read_file).with(target).and_return(ordinary_line + ' user second_target')

    mod.run

    expect(stored_loot).to be_empty
  end

  it 'rereads and stores the same file on a second invocation' do
    expect(mod).to receive(:read_file).with(target).twice.and_return(file_data)

    mod.run
    mod.run

    expect(reported_csv).to eq([native_csv, native_csv])
  end
end
