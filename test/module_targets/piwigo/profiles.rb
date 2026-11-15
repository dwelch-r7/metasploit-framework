# frozen_string_literal: true

require 'json'

# Pinned application identity and expected native behavior for each small stack.
module PiwigoProfiles
  OWNER = 'auxiliary/gather/piwigo_cve_2023_26876'
  RELEASES = JSON.parse(File.read(File.join(__dir__, 'releases.json'))).freeze
  PROFILES = JSON.parse(File.read(File.join(__dir__, 'profiles.json'))).freeze
  ADMIN = 'module_admin'
  PASSWORD = 'module-target-piwigo-password'
  MEMBERS = ['module_reader', 'owned,comma;semi', 'owned_é雪'].freeze

  def self.fetch
    PROFILES.fetch(ENV.fetch('PIWIGO_PROFILE', 'piwigo'))
  end
end
