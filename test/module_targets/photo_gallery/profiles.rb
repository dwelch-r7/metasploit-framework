# frozen_string_literal: true

require 'json'

# Explicit genuine releases and distinct functional execution paths.
module PhotoGalleryProfiles
  OWNER = 'auxiliary/gather/wp_photo_gallery_sqli'
  RELEASES = JSON.parse(File.read(File.join(__dir__, 'releases.json'))).freeze
  PROFILES = JSON.parse(File.read(File.join(__dir__, 'profiles.json'))).freeze

  def self.fetch
    PROFILES.fetch(ENV.fetch('PHOTO_GALLERY_PROFILE', 'photo_gallery'))
  end
end
