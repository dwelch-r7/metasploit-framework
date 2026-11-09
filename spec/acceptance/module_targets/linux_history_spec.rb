require 'acceptance_spec_helper'
require 'base64'

RSpec.describe 'Linux account history collection targets' do
  include_context 'module target'
  include_context 'wait_for_expect'
  include_context 'native Linux session'

  let_it_be(:native_users) do
    %w[root labuser].to_h do |user|
      report = JSON.parse(target_exec('linux', 'runuser', '-u', user, '--', 'python3', '-W', 'ignore::DeprecationWarning', '/opt/history-native-probe.py'))
      expect(report.fetch('username')).to eq(user)
      expect(report.fetch('uid')).to eq(user == 'root' ? 0 : 1000)
      expect(report.fetch('hostname')).to eq('module-target-linux-history')
      File.write(File.join(target_runtime.fetch('artifacts'), "native-#{user}-preflight.json"), JSON.pretty_generate(report))
      [user, report]
    end
  end

  before(:all) { native_users }

  %w[root labuser].each do |user|
    {
      'shell' => { payload: 'linux/x64/shell_reverse_tcp', format: 'elf', file: 'shell-session.elf' },
      'meterpreter' => { payload: 'linux/x64/meterpreter_reverse_tcp', format: 'elf', file: 'meterpreter-session.elf' }
    }.each do |kind, delivery|
      context "#{user} #{kind}" do
        let(:session_id) { open_native_session(kind, delivery, user: user) }
        let(:native) { native_users.fetch(user) }

        after do
          target_exec('linux', 'rm', '-f', '/tmp/module-target-session-proof', '/tmp/shell-session.elf', '/tmp/meterpreter-session.elf')
        end

        it 'collects actual readable histories and omits empty or missing data' do
          # Root enumerates every native system account. Repeat the bounded
          # current-user path; collection only reads target state.
          (user == 'root' ? 1 : 2).times do
            output = run_target_module('post/linux/gather/enum_users_history', 'linux', { 'SESSION' => session_id }, allow_errors: true, endpoint_options: {}, command_timeout: 180)
            verify_read_errors(output, user)
            expect(output).to include('Post module execution completed')
            expected = user == 'root' ? %w[root labuser historyuser] : ['labuser']
            expected.each do |owner|
              {
                'ash' => '.ash_history', 'bash' => '.bash_history',
                'MySQL' => '.mysql_history', 'PostgreSQL' => '.psql_history',
                'MongoDB' => '.dbshell', 'Vim' => '.viminfo'
              }.each do |label, filename|
                expect(loot_body(output, "#{label} history for #{owner}")).to eq(decode(native.fetch('histories').fetch(owner).fetch(filename).fetch('data')))
              end
              expect(output).not_to include("zsh history for #{owner} stored in", "csh history for #{owner} stored in")
            end
            expect(loot_body(output, 'Last logs')).to eq(decode(native.fetch('logs')).chomp)
            if user == 'root'
              expect(loot_body(output, 'Sudoers')).to eq(file_bytes(native, '/etc/sudoers'))
            else
              expect(output).not_to include('Sudoers stored in', 'history for root stored in', 'history for historyuser stored in')
            end
          end
        end

        it 'collects exact hashes twice as root or refuses the unprivileged session' do
          2.times do
            output = run_target_module('post/linux/gather/hashdump', 'linux', { 'SESSION' => session_id }, allow_errors: true, endpoint_options: {}, command_timeout: 90)
            expect(output).to include('Post module execution completed')
            if user == 'root'
              expect(output).not_to include('[-]')
              expect(loot_body(output, 'passwd saved in:')).to eq(file_bytes(native, '/etc/passwd'))
              expect(loot_body(output, 'Shadow saved in:')).to eq(file_bytes(native, '/etc/shadow'))
              expect(loot_body(output, 'opasswd saved in:')).to eq(file_bytes(native, '/etc/security/opasswd'))
              hashes = loot_body(output, 'Unshadowed Password File:')
              passwd = file_bytes(native, '/etc/passwd').lines.to_h { |line| [line.split(':', 2).first, line] }
              shadow = file_bytes(native, '/etc/shadow').lines.map { |line| line.split(':', 3).take(2) }.to_h
              expected = shadow.filter_map do |owner, hash|
                next if hash.empty? || hash.start_with?('!') || hash == '*'

                passwd.fetch(owner).sub(':x:', ":#{hash}:")
              end.join
              expect(hashes).to eq(expected)
              expect(hashes).not_to include('lockeduser:')
              %w[root labuser historyuser].each { |owner| expect(output).to include(passwd.fetch(owner).sub(':x:', ":#{shadow.fetch(owner)}:").strip) }
            else
              expect(output).to include('Shadow file must be readable in order to dump hashes')
              expect(output).not_to include('saved in:', 'Unshadowed Password File:')
            end
          end
        end
      end
    end
  end

  def decode(value)
    Base64.strict_decode64(value)
  end

  def file_bytes(native, filename)
    decode(native.fetch('files').fetch(filename).fetch('data'))
  end

  def loot_body(output, label)
    separator = label.end_with?(':') ? ' ' : ' stored in '
    path = output[/#{Regexp.escape(label + separator)}(.+)$/, 1]&.strip
    expect(path).not_to be_nil, output
    expect(File.expand_path(path)).to start_with(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot/'))
    File.binread(path)
  end

  def verify_read_errors(output, user)
    filenames = output.lines.select { |line| line.include?('[-]') }.map do |line|
      filename = line[%r{Failed to open file: (/[^:]+): core_channel_open: Operation failed: 1}, 1]
      expect(filename).not_to be_nil, line
      filename
    end.uniq
    return if filenames.empty?

    states = JSON.parse(target_exec('linux', 'runuser', '-u', user, '--', 'python3', '-c', 'import json,os,sys; print(json.dumps({path: os.access(path, os.R_OK) for path in json.loads(sys.argv[1])}))', JSON.generate(filenames)))
    filenames.each do |filename|
      expect(states.fetch(filename)).to be(false), filename
    end
  end
end
