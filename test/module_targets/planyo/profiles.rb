# frozen_string_literal: true

require 'json'

# Genuine source releases, file inputs and distinct deployment states.
module PlanyoProfiles
  OWNER = 'auxiliary/gather/wp_planyo_lfi_cve_2026_3576'
  RELEASES = JSON.parse(File.read(File.join(__dir__, 'releases.json'))).freeze
  PROFILES = JSON.parse(File.read(File.join(__dir__, 'profiles.json'))).freeze
  FILES = JSON.parse(File.read(File.join(__dir__, 'files.json'))).freeze

  def self.fetch
    PROFILES.fetch(ENV.fetch('PLANYO_PROFILE', 'planyo'))
  end
end
