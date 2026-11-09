##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'CouchDB Login Utility',
        'Description' => %q{
          This module tests CouchDB logins on a range of
          machines and report successful logins.
        },
        'Author' => [
          'espreto <robertoespreto[at]gmail.com>'
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS, ACCOUNT_LOCKOUTS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(5984),
        OptString.new('TARGETURI', [false, 'TARGETURI for CouchDB. Default here is /', '/']),
        OptPath.new('USERPASS_FILE', [
          false, 'File containing users and passwords separated by space, one pair per line',
          File.join(Msf::Config.data_directory, 'wordlists', 'http_default_userpass.txt')
        ]),
        OptPath.new('USER_FILE', [
          false, 'File containing users, one per line',
          File.join(Msf::Config.data_directory, 'wordlists', 'http_default_users.txt')
        ]),
        OptPath.new('PASS_FILE', [
          false, 'File containing passwords, one per line',
          File.join(Msf::Config.data_directory, 'wordlists', 'http_default_pass.txt')
        ]),
        OptBool.new('USER_AS_PASS', [ false, 'Try the username as the password for all users', false]),
      ]
    )

    deregister_options('HttpUsername', 'HttpPassword')
  end

  def run_host(_ip)
    user = datastore['HttpUsername'].to_s
    pass = datastore['HttpPassword'].to_s

    if user.strip.empty?
      each_user_pass do |username, password|
        do_login(username, password)
      end
    else
      do_login(user, pass)
    end
    nil
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :password
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def do_login(user, pass)
    vprint_status("Trying username:'#{user}' with password:'#{pass}'")

    # User records require admin privileges; the identity endpoint validates
    # ordinary accounts too: https://docs.couchdb.org/en/stable/api/server/authn.html#session
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '_session'),
      'method' => 'GET',
      'authorization' => basic_auth(user, pass)
    })

    unless res
      print_error('HTTP connection failed, aborting')
      return :abort
    end

    return :skip_pass unless res.code == 200

    document = res.get_json_document
    return :skip_pass unless document.is_a?(Hash) && document['ok'] == true

    identity = document['userCtx']
    return :skip_pass unless identity.is_a?(Hash) && !user.to_s.empty? && identity['name'] == user

    print_good("#{peer} - Successful login with: '#{user}' : '#{pass}'")

    report_cred(
      ip: rhost,
      port: rport,
      service_name: 'couchdb',
      user: user,
      password: pass,
      proof: res.body
    )

    :next_user
  rescue ::Rex::ConnectionError, ::Errno::ECONNREFUSED, ::Errno::ETIMEDOUT => e
    elog('CouchDB authentication request failed', error: e)
    print_error('HTTP connection failed, aborting')
    return :abort
  end
end
