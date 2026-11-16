# frozen_string_literal: true

require 'json'

# Pins the real plugin releases and keeps each functional profile explicit.
module WpDiscuzProfiles
  OWNER = 'exploit/unix/webapp/wp_wpdiscuz_unauthenticated_file_upload'
  DEFAULT_PAYLOAD = 'php/meterpreter/reverse_tcp'
  RELEASES = JSON.parse(File.read(File.join(__dir__, 'releases.json'))).freeze
  PROFILES = JSON.parse(File.read(File.join(__dir__, 'profiles.json'))).freeze

  def self.fetch
    PROFILES.fetch(ENV.fetch('WPDISCUZ_PROFILE', 'wpdiscuz'))
  end
end
