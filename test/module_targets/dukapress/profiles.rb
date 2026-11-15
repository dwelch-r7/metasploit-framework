# frozen_string_literal: true

require 'json'

# Owns source pins, runtime identity and file contracts for every profile.
module DukapressProfiles
  OWNER = 'auxiliary/scanner/http/wp_dukapress_file_read'
  RELEASES = JSON.parse(File.read(File.join(__dir__, 'releases.json'))).freeze
  FILES = JSON.parse(File.read(File.join(__dir__, 'files.json'))).freeze
  RUNTIME = JSON.parse(File.read(File.join(__dir__, 'runtime.json'))).freeze
  PROFILES = JSON.parse(File.read(File.join(__dir__, 'profiles.json'))).freeze

  def self.fetch
    PROFILES.fetch(ENV.fetch('DUKAPRESS_PROFILE', 'dukapress'))
  end
end
