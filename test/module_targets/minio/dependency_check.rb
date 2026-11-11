# frozen_string_literal: true

require 'json'
require 'digest'

# Executed only inside the separately reviewed cached canonical Framework image.
expected = JSON.parse(File.read(File.join(__dir__, 'dependency_sources.json')))
actual = expected.to_h do |name, definition|
  spec = Gem::Specification.find_by_name(name)
  raise ArgumentError, "Loaded dependency version differs: #{name}" unless spec.version.to_s == definition.fetch('version')

  definition.fetch('files').each do |relative, sha|
    file = File.join(spec.full_gem_path, relative)
    raise ArgumentError, "Dependency source differs: #{name}/#{relative}" unless File.file?(file) && !File.symlink?(file) && Digest::SHA256.file(file).hexdigest == sha
  end
  [name, { version: spec.version.to_s, files: definition.fetch('files').length, gem_path: spec.full_gem_path }]
end
puts JSON.generate(actual)
