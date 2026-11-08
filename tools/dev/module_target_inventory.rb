#!/usr/bin/env ruby
# frozen_string_literal: true

require 'digest'
require 'json'
require 'yaml'

# Static queue, not a claim of container feasibility or functional coverage.
root = File.expand_path('../..', __dir__)
labs = Dir[File.join(root, 'test/module_targets/*/manifest.yml')]
registered = labs.each_with_object({}) do |path, result|
  YAML.safe_load_file(path).fetch('modules').each do |fullname|
    (result[fullname] ||= []) << File.basename(File.dirname(path))
  end
end
types = { 'exploits' => 'exploit', 'payloads' => 'payload', 'encoders' => 'encoder', 'nops' => 'nop' }
inventory = Dir[File.join(root, 'modules/**/*.rb')].map do |path|
  relative = path.delete_prefix("#{root}/")
  parts = relative.delete_prefix('modules/').delete_suffix('.rb').split('/')
  parts[0] = types.fetch(parts[0], parts[0])
  source_reference = parts.join('/')
  # Stage/stager files are components; their source path is not a selectable
  # payload fullname. Review composed payloads with the existing session suites.
  fullname = parts.first == 'payload' ? nil : source_reference
  document = "documentation/modules/#{fullname}.md" if fullname
  document ||= ''
  doc_path = File.join(root, document)
  documentation = File.file?(doc_path) ? File.read(doc_path) : ''
  source = File.read(path)
  {
    fullname: fullname,
    source_reference: source_reference,
    source: relative,
    source_sha256: Digest::SHA256.hexdigest(source),
    documentation: File.file?(doc_path) ? document : nil,
    documented_container_hint: documentation.match?(/docker|podman|container|compose/i),
    check_implementation: source.match?(/^\s*def check(?:_host)?\b/),
    labs: registered.fetch(fullname, []),
    review_state: registered.key?(fullname) ? 'registered_not_proof_of_pass' : 'pending_review'
  }
end
if ARGV == ['--json']
  puts JSON.pretty_generate(inventory)
elsif ARGV.empty?
  puts "Module source files: #{inventory.length}"
  puts "Registered in a lab: #{inventory.count { |entry| !entry[:labs].empty? }}"
  puts "Documentation mentions containers: #{inventory.count { |entry| entry[:documented_container_hint] }}"
  puts 'Prioritize existing reproducible labs, reusable service families, then version-specific applications.'
  puts 'Container hints require review; missing hints do not establish infeasibility.'
  puts 'Use --json for the complete queue, including source digests to identify changed modules.'
else
  warn 'Usage: ruby tools/dev/module_target_inventory.rb [--json]'
  exit 2
end
