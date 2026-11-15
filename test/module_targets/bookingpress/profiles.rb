# frozen_string_literal: true

require 'json'

# Owns the actual source and deployment expectations for every BookingPress lab.
module BookingpressProfiles
  OWNER = 'auxiliary/gather/wp_bookingpress_category_services_sqli'
  RELEASES = JSON.parse(File.read(File.join(__dir__, 'releases.json'))).freeze
  PROFILES = JSON.parse(File.read(File.join(__dir__, 'profiles.json'))).freeze

  # @return [Hash] Selected profile's exact release and deployment settings
  def self.fetch
    PROFILES.fetch(ENV.fetch('BOOKINGPRESS_PROFILE', 'bookingpress'))
  end
end
