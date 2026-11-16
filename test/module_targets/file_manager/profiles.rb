# frozen_string_literal: true

require 'json'

# Explicit genuine application versions and functional execution paths.
module FileManagerProfiles
  OWNER = 'exploit/multi/http/wp_file_manager_rce'
  DEFAULT_PAYLOAD = 'php/meterpreter/reverse_tcp'
  RELEASES = JSON.parse(File.read(File.join(__dir__, 'releases.json'))).freeze
  PROFILES = JSON.parse(File.read(File.join(__dir__, 'profiles.json'))).freeze

  def self.fetch
    PROFILES.fetch(ENV.fetch('FILE_MANAGER_PROFILE', 'file_manager'))
  end
end
