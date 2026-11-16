# frozen_string_literal: true

require 'json'

# Deployment states shared by native controls and public module tests.
module ElasticsearchMemoryProfiles
  OWNER = 'auxiliary/scanner/http/elasticsearch_memory_disclosure'
  DIRECTORY = __dir__
  PROFILES = JSON.parse(File.read(File.join(DIRECTORY, 'profiles.json'))).freeze

  def self.fetch
    PROFILES.fetch(ENV.fetch('ELASTICSEARCH_MEMORY_PROFILE', 'elasticsearch_memory'))
  end
end
