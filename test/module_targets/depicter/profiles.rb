# frozen_string_literal: true

require 'json'

# Explicit genuine releases and distinct functional execution paths.
module DepicterProfiles
  OWNER = 'auxiliary/gather/wp_depicter_sqli_cve_2025_2011'
  RELEASES = JSON.parse(File.read(File.join(__dir__, 'releases.json'))).freeze
  PROFILES = JSON.parse(File.read(File.join(__dir__, 'profiles.json'))).freeze

  def self.fetch
    PROFILES.fetch(ENV.fetch('DEPICTER_PROFILE', 'depicter'))
  end
end
