# frozen_string_literal: true

require 'json'

# Owns the shared source pins and native expectations for every profile.
module PostSmtpProfiles
  OWNER = 'auxiliary/admin/http/wp_post_smtp_acct_takeover'
  RELEASES = JSON.parse(File.read(File.join(__dir__, 'releases.json'))).freeze
  PROFILES = JSON.parse(File.read(File.join(__dir__, 'profiles.json'))).freeze

  def self.fetch
    PROFILES.fetch(ENV.fetch('POST_SMTP_PROFILE', 'post_smtp'))
  end
end
