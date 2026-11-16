# frozen_string_literal: true

require 'json'

# Genuine Core releases and deployment prerequisites, with one stack per profile.
module DrupalPgsqlProfiles
  OWNER = 'auxiliary/scanner/http/drupal_pgsql_entityquery_sqli'
  RELEASES = JSON.parse(File.read(File.join(__dir__, 'releases.json'))).freeze
  PROFILES = JSON.parse(File.read(File.join(__dir__, 'profiles.json'))).freeze

  def self.fetch
    PROFILES.fetch(ENV.fetch('DRUPAL_PGSQL_PROFILE', 'drupal_pgsql'))
  end
end
