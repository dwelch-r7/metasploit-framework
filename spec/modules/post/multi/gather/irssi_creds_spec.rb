require 'msfenv'
require 'msf/base'

RSpec.describe 'Irssi raw configuration collection' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = File.expand_path('../../../../../modules/post/multi/gather/irssi_creds.rb', __dir__)
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:framework) { double('Framework', datastore: Msf::DataStore.new) }
  let(:session) { double('Command shell session') }
  let(:target) { '/root/.irssi/config' }
  let(:fixtures) { File.expand_path('../../../../file_fixtures/modules/post/multi/gather/irssi_creds', __dir__) }
  let(:fixture_name) { 'plain.config' }
  let(:file_data) { File.binread(File.join(fixtures, fixture_name)) }
  let(:catalogue) { JSON.parse(File.binread(File.join(fixtures, 'catalogue.json'))) }
  let(:stored_loot) { [] }

  # Exact files consumed by native Irssi 1.2.3/ngIRCd 26.1 controls on
  # 2026-11-18. plain.config is also exact raw loot from the original owner
  # over a genuine shell with PostgreSQL reporting. Transport, Framework,
  # persistence and output are doubled; owner detection/run logic is real.
  # A match selects raw evidence. It does not establish active authentication:
  # wrong.config and commented.config remain intentionally collectible.
  before do
    allow(mod).to receive_messages(framework: framework, session: session)
    allow(mod).to receive(:enum_user_directories).and_return(['/root'])
    allow(mod).to receive(:file?).and_return(false)
    allow(mod).to receive(:file?).with(target).and_return(true)
    allow(mod).to receive(:read_file).with(target).and_return(file_data)
    allow(mod).to receive(:store_loot) do |*args|
      stored_loot << args
      '/loot/irssi-config'
    end
    allow(mod).to receive(:print_status)
    allow(mod).to receive(:print_error)
    allow(mod).to receive(:print_good)
  end

  shared_examples 'a native Irssi file' do |file_name|
    let(:fixture_name) { file_name }

    it "preserves raw-evidence selection for #{file_name}" do
      contains_password = !catalogue.fetch(file_name).fetch('expected_passwords').empty?
      expected_loot = contains_password ? [['irssi config file', 'text/plain', session, file_data, target, 'IRC Password']] : []

      detected = mod.contains_passwords?(target)
      mod.run

      expect([detected, stored_loot]).to eq([contains_password, expected_loot])
    end
  end

  it_behaves_like 'a native Irssi file', 'plain.config'
  it_behaves_like 'a native Irssi file', 'tabs.config'
  it_behaves_like 'a native Irssi file', 'compact.config'
  it_behaves_like 'a native Irssi file', 'wrong.config'
  it_behaves_like 'a native Irssi file', 'missing-password.config'
  it_behaves_like 'a native Irssi file', 'commented.config'

  it 'preserves detection output and raw loot without creating credential cores' do
    expect(mod).not_to receive(:create_credential)
    expect(mod).to receive(:print_good).with("Found IRC password(s) of module-target-irc-password in irssi config at #{target}")

    mod.run

    expect(stored_loot).to eq([['irssi config file', 'text/plain', session, file_data, target, 'IRC Password']])
  end

  context 'with legacy NickServ detection' do
    # Compatibility-only strings taken from the owner pattern/examples.
    # No real IRC services were available to qualify NickServ authentication.
    it 'retains the /msg identify pattern' do
      data = 'autosendcmd = "/msg nickserv identify example_password ;wait 2000";'
      allow(mod).to receive(:read_file).with(target).and_return(data)

      expect(mod.contains_passwords?(target)).to be(true)
    end

    it 'retains the /^msg identify pattern' do
      data = 'autosendcmd = "/^msg nickserv identify example_password ;wait 2000";'
      allow(mod).to receive(:read_file).with(target).and_return(data)

      expect(mod.contains_passwords?(target)).to be(true)
    end
  end

  it 'retains inline network-password matching' do
    # Explicit variation of the captured plain assignment, without native auth.
    data = 'servers = ({ address = "127.0.0.1"; password = "example_password"; });'
    allow(mod).to receive(:read_file).with(target).and_return(data)

    expect(mod.contains_passwords?(target)).to be(true)
  end

  it 'does not detect passwords in an empty file' do
    allow(mod).to receive(:read_file).with(target).and_return('')

    expect(mod.contains_passwords?(target)).to be(false)
  end

  it 'handles the nil return permitted by the session file helper' do
    # Synthetic helper boundary; no nil-read race was reproduced natively.
    allow(mod).to receive(:read_file).with(target).and_return(nil)

    expect(mod.contains_passwords?(target)).to be(false)
  end

  it 'continues after a nil read to another user configuration' do
    # Synthetic helper boundary; the native cohort used readable root files.
    other_target = '/home/lab user/.irssi/config'
    allow(mod).to receive(:enum_user_directories).and_return(['/root', '/home/lab user'])
    allow(mod).to receive(:file?).with(other_target).and_return(true)
    allow(mod).to receive(:read_file).with(target).and_return(nil)
    allow(mod).to receive(:read_file).with(other_target).and_return(file_data)

    mod.run

    expect(stored_loot).to eq([['irssi config file', 'text/plain', session, file_data, other_target, 'IRC Password']])
  end

  it 'does not read or store loot when no user configuration exists' do
    allow(mod).to receive(:file?).with(target).and_return(false)
    expect(mod).not_to receive(:read_file)

    mod.run

    expect(stored_loot).to be_empty
  end

  it 'stores the same raw file on a second invocation' do
    mod.run
    mod.run

    expect(stored_loot).to eq([
      ['irssi config file', 'text/plain', session, file_data, target, 'IRC Password'],
      ['irssi config file', 'text/plain', session, file_data, target, 'IRC Password']
    ])
  end

  context 'with NickServ authentication commands' do
    let(:fixtures) { File.expand_path('../../../../file_fixtures/modules/post/multi/gather/irssi_creds/nickserv', __dir__) }
    let(:fixture_name) { 'autosend-lower.config' }

    # Exact Irssi 1.2.3 files and IDENTIFY/STATUS wire excerpts from real
    # ngIRCd 26.1/Atheme 7.2.12 controls are kept beside these fixtures.
    # Session transport, Framework, output and persistence remain doubled.
    # Wrong and commented credentials select raw evidence without proving auth.
    before do
      expect(mod).not_to receive(:create_credential)
    end

    shared_examples 'NickServ raw evidence' do |file_name, authentication_type, arguments|
      let(:fixture_name) { file_name }

      it "reports complete authentication data and raw evidence for #{file_name}" do
        mod.run

        if arguments
          expect(mod).to have_received(:print_good).with("Found #{authentication_type} of #{arguments} in irssi config at #{target}")
          expect(stored_loot).to eq([['irssi config file', 'text/plain', session, file_data, target, 'IRC Password']])
        else
          expect([mod.contains_passwords?(target), stored_loot]).to eq([false, []])
        end
      end
    end

    it_behaves_like 'NickServ raw evidence', 'autosend-lower.config', 'IRC password(s)', 'module-target-nickserv-password'
    it_behaves_like 'NickServ raw evidence', 'autosend-caret.config', 'IRC password(s)', 'module-target-nickserv-password'
    it_behaves_like 'NickServ raw evidence', 'autosend-capital.config', 'IRC password(s)', 'module-target-nickserv-password'
    it_behaves_like 'NickServ raw evidence', 'autosend-command-case.config', 'IRC password(s)', 'module-target-nickserv-password'
    it_behaves_like 'NickServ raw evidence', 'autosend-account.config', 'NickServ IDENTIFY authentication data', 'labguest module-target-nickserv-password'
    it_behaves_like 'NickServ raw evidence', 'autosend-wrong.config', 'IRC password(s)', 'module-target-nickserv-wrong'
    it_behaves_like 'NickServ raw evidence', 'commented-autosend.config', 'IRC password(s)', 'module-target-nickserv-comment'
    it_behaves_like 'NickServ raw evidence', 'password-free.config', nil, nil

    it 'retains the complete account-first arguments sent on the native wire' do
      native_wire = JSON.parse(File.binread(File.join(fixtures, 'native-wire.json')))
      # Literal wire capture, independent of the configuration matcher.
      expect(native_wire.fetch('autosend-account.config').fetch('identify_sent')).to eq(['<< PRIVMSG nickserv :identify labguest module-target-nickserv-password'])
    end

    context 'with two IDENTIFY arguments' do
      let(:fixture_name) { 'autosend-account.config' }

      it 'does not label the first argument as a password' do
        mod.run

        expect(mod).not_to have_received(:print_good).with(a_string_starting_with('Found IRC password(s) of'))
      end

      it 'preserves password-before-nick arguments without guessing the order' do
        # Synthetic compatibility variation from the official Irssi manual's
        # OFTC ordering; an OFTC service was not run in the native cohort.
        data = file_data.sub('labguest module-target-nickserv-password', 'module-target-nickserv-password labguest')
        allow(mod).to receive(:read_file).with(target).and_return(data)

        expect(mod).to receive(:print_good).with("Found NickServ IDENTIFY authentication data of module-target-nickserv-password labguest in irssi config at #{target}")

        expect(mod.contains_passwords?(target)).to be(true)
      end

      it 'preserves internal whitespace in the complete authentication arguments' do
        # Synthetic formatting variation; the native capture used one space.
        data = file_data.sub('labguest module-target-nickserv-password', "labguest \t module-target-nickserv-password")
        allow(mod).to receive(:read_file).with(target).and_return(data)

        expect(mod).to receive(:print_good).with("Found NickServ IDENTIFY authentication data of labguest \t module-target-nickserv-password in irssi config at #{target}")

        expect(mod.contains_passwords?(target)).to be(true)
      end

      it 'keeps network-password output separate from ambiguous IDENTIFY arguments' do
        data = file_data + 'password = "network-secret";'
        allow(mod).to receive(:read_file).with(target).and_return(data)
        expect(mod).to receive(:print_good).with("Found IRC password(s) of network-secret in irssi config at #{target}")
        expect(mod).to receive(:print_good).with("Found NickServ IDENTIFY authentication data of labguest module-target-nickserv-password in irssi config at #{target}")

        expect(mod.contains_passwords?(target)).to be(true)
      end

      it 'preserves exact raw loot and metadata on a second invocation' do
        2.times { mod.run }

        expect(stored_loot).to eq([
          ['irssi config file', 'text/plain', session, file_data, target, 'IRC Password'],
          ['irssi config file', 'text/plain', session, file_data, target, 'IRC Password']
        ])
      end
    end

    it 'stops the single password before an adjacent command separator' do
      # Synthetic command-boundary variation of the native lower-case config.
      data = file_data.sub('module-target-nickserv-password"', 'module-target-nickserv-password;wait 2000"')
      allow(mod).to receive(:read_file).with(target).and_return(data)
      expect(mod).to receive(:print_good).with("Found IRC password(s) of module-target-nickserv-password in irssi config at #{target}")

      expect(mod.contains_passwords?(target)).to be(true)
    end

    it 'trims command whitespace without adding it to the single password' do
      data = file_data.sub('identify module-target-nickserv-password"', "identify\tmodule-target-nickserv-password \t\"")
      allow(mod).to receive(:read_file).with(target).and_return(data)
      expect(mod).to receive(:print_good).with("Found IRC password(s) of module-target-nickserv-password in irssi config at #{target}")

      expect(mod.contains_passwords?(target)).to be(true)
    end

    shared_examples 'not a NickServ credential' do |command|
      it "does not collect #{command}" do
        # Synthetic negative boundaries, not native authentication claims.
        allow(mod).to receive(:read_file).with(target).and_return("autosendcmd = \"#{command}\";")

        mod.run

        expect([mod.contains_passwords?(target), stored_loot]).to eq([false, []])
      end
    end

    it_behaves_like 'not a NickServ credential', '/msg nickserv identify'
    it_behaves_like 'not a NickServ credential', '/msg nickserv identify   '
    it_behaves_like 'not a NickServ credential', '/msg nickserv identify ;wait 2000'
    it_behaves_like 'not a NickServ credential', '/msg notnickserv identify example_password'
    it_behaves_like 'not a NickServ credential', '/msg nickserv identifying example_password'
    it_behaves_like 'not a NickServ credential', '/msg nickserv status example_password'
  end
end
