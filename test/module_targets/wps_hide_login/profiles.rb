# frozen_string_literal: true

require 'json'

# Keep native expectations and collection scope in one component-owned table.
module WpsHideLoginProfiles
  OWNER = 'auxiliary/scanner/http/wp_wps_hide_login_revealer'
  RELEASES = JSON.parse(File.read(File.join(__dir__, 'releases.json'))).freeze
  PROFILES = {
    'root' => { prefix: '', release: 'affected', slug: 'module-login-alpha', disclosure: true, examples: 3 },
    'prefix' => { prefix: '/wordpress', release: 'affected', slug: 'module-login-beta', disclosure: false, examples: 1 },
    'fixed' => { prefix: '', release: 'fixed', slug: 'module-login-fixed', disclosure: false, examples: 1 },
    'fixed_prefix' => { prefix: '/wordpress', release: 'fixed', slug: 'module-login-fixed-prefix', disclosure: false, examples: 1 },
    'absent' => { prefix: '', release: nil, slug: nil, disclosure: false, examples: 1 },
    'unrelated' => { prefix: '', release: nil, slug: nil, disclosure: false, unrelated: true, examples: 1 }
  }.transform_values(&:freeze).freeze

  def self.fetch
    PROFILES.fetch(ENV.fetch('WPS_HIDE_PROFILE', 'root'))
  end
end
