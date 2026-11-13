# frozen_string_literal: true

require 'digest'

# Slim Debian deliberately excludes metadata. Reject any other missing file or
# checksum difference, while retaining checks against the signed package data.
module FreeSwitchExecutionPackages
  CONFIGURATION = File.binread(File.join(__dir__, 'dpkg-exclusions.conf')).freeze

  def self.verify(output, configuration)
    unless Digest::SHA256.hexdigest(configuration) == Digest::SHA256.hexdigest(CONFIGURATION)
      raise ArgumentError, 'Unexpected native dpkg exclusion configuration'
    end

    rules = configuration.lines.filter_map do |line|
      match = line.match(/\Apath-(exclude|include)\s+(\S+)\s*\z/)
      [match[1], match[2]] if match
    end
    output.lines.map do |line|
      match = line.strip.match(%r{\Amissing\s+(/\S+)\z})
      raise ArgumentError, "Unexpected package verification difference: #{line.strip}" unless match

      path = match[1]
      rule = rules.reverse.find { |_operation, pattern| File.fnmatch?(pattern, path) }
      raise ArgumentError, "Unexpected missing installed package file: #{path}" unless rule&.first == 'exclude'

      path
    end
  end
end
