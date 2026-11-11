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
reviews = YAML.safe_load_file(File.join(root, 'test/module_targets/reviews.yml')).fetch('modules')
types = { 'exploits' => 'exploit', 'payloads' => 'payload', 'encoders' => 'encoder', 'nops' => 'nop' }
inventory = Dir[File.join(root, 'modules/**/*.{rb,py,go}')].map do |path|
  relative = path.delete_prefix("#{root}/")
  language = File.extname(path).delete_prefix('.')
  source = File.binread(path)
  parts = relative.delete_prefix('modules/').delete_suffix(".#{language}").split('/')
  parts[0] = types.fetch(parts[0], parts[0])
  source_reference = parts.join('/')
  # Stage/stager files are components; their source path is not a selectable
  # payload fullname. Review composed payloads with the existing session suites.
  source_role = if parts.first == 'payload'
                  'payload_component'
                elsif File.basename(path).start_with?('_') || (language == 'go' && !source.match?(/^package main$/))
                  'supporting_code'
                else
                  'module_candidate'
                end
  fullname = source_role == 'module_candidate' ? source_reference : nil
  document = "documentation/modules/#{fullname}.md" if fullname
  document ||= ''
  doc_path = File.join(root, document)
  documentation = File.file?(doc_path) ? File.read(doc_path) : ''
  digest = Digest::SHA256.hexdigest(source)
  review = reviews[fullname]
  module_labs = registered.fetch(fullname, []).dup
  if review && review.fetch('source_sha256') == digest
    module_labs.concat(review.fetch('lab_profiles', {}).keys)
  end
  module_labs.uniq!
  review_state = if review && review.fetch('source_sha256') != digest
                   'review_stale'
                 elsif !module_labs.empty?
                   'registered_not_proof_of_pass'
                 elsif review
                   review.fetch('disposition')
                 else
                   'pending_review'
                 end
  {
    fullname: fullname,
    source_reference: source_reference,
    source: relative,
    language: language,
    source_role: source_role,
    source_sha256: digest,
    documentation: File.file?(doc_path) ? document : nil,
    documented_container_hint: documentation.match?(/docker|podman|container|compose/i),
    check_implementation: source.match?(/^\s*def check(?:_host)?\b/),
    labs: module_labs,
    feasibility_review: review,
    review_state: review_state
  }
end
if ARGV == ['--json']
  puts JSON.pretty_generate(inventory)
elsif ARGV.empty?
  puts "Module source files: #{inventory.length}"
  puts "By language: #{inventory.group_by { |entry| entry[:language] }.transform_values(&:length)}"
  puts "Registered in a lab: #{inventory.count { |entry| !entry[:labs].empty? }}"
  puts "Documentation mentions containers: #{inventory.count { |entry| entry[:documented_container_hint] }}"
  puts "Individual target reviews: #{inventory.count { |entry| entry[:feasibility_review] }} (#{inventory.count { |entry| entry[:review_state] == 'review_stale' }} stale)"
  puts 'Prioritize existing reproducible labs, reusable service families, then version-specific applications.'
  puts 'Container hints require review; missing hints do not establish infeasibility.'
  puts 'Use --json for the complete queue, including source digests to identify changed modules.'
else
  warn 'Usage: ruby tools/dev/module_target_inventory.rb [--json]'
  exit 2
end
