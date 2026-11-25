# frozen_string_literal: true

require 'csv'
require 'open3'
require 'pathname'
require 'rbs'
require 'rbconfig'
require 'ripper'

# Enforce the pilot's declared scope and reject silent loss of checking.
module FrameworkTypeCheck
  REQUIRED_FILES = %w[lib/rex/proto/dcerpc/uuid.rb lib/rex/proto/dcerpc/packet.rb].freeze

  def self.untyped?(source)
    RBS::Parser.lex(source).value.any? { |token| token.type == :kUNTYPED }
  end

  def self.steep(root, *)
    stdout, stderr, status = Open3.capture3(
      RbConfig.ruby, Gem.bin_path('steep', 'steep'), *, chdir: root
    )
    warn stderr unless stderr.empty?
    # Some checker failures have historically been logged while the command
    # still returned success. Treat that provider failure as unsuccessful analysis.
    fatal = [stdout, stderr].any? { |stream| stream.include?('FATAL: [Steep ') }
    [stdout, status.success? && !fatal]
  end

  def self.run(root: File.expand_path('../..', __dir__))
    root = Pathname(root)
    Dir.glob(root.join('typing/**/*.rbs')).each do |path|
      if untyped?(File.read(path))
        warn "Untyped declaration in #{path}"
        return false
      end
    end

    output, success = steep(root, 'check', '--no-daemon', '--jobs=1', '--validate=library')
    puts output
    return false unless success

    output, success = steep(root, 'stats', '--format=csv', '--jobs=1')
    return false unless success

    rows = CSV.parse(output, headers: true)
    unless %w[File Status].all? { |column| rows.headers.include?(column) } && rows.headers.include?('Untyped calls')
      warn 'Missing type-check statistics columns'
      return false
    end
    missing = REQUIRED_FILES - rows.map { |row| row.fetch('File') }
    unless missing.empty?
      warn "Required connected files are not checked: #{missing.join(', ')}"
      return false
    end

    rows.each do |row|
      # Ripper locates actual comments; the RBS lexer distinguishes type keywords
      # from strings and ordinary prose. Avoid banning the word in documentation.
      Ripper.lex(root.join(row.fetch('File')).read).each do |_position, event, comment, _state|
        next unless event == :on_comment && comment.match?(/\A#(?::|\s*@type\b)/)

        if untyped?(comment.delete_prefix('#'))
          warn "Untyped annotation in #{row.fetch('File')}"
          return false
        end
      end
      unless row.fetch('Status') == 'success' && Integer(row.fetch('Untyped calls'), 10).zero?
        warn "Unchecked calls or unsuccessful analysis in #{row.fetch('File')}"
        return false
      end
    end

    puts output
    true
  rescue CSV::MalformedCSVError, ArgumentError, KeyError => e
    warn "Invalid type-check evidence: #{e.message}"
    false
  end
end

exit(FrameworkTypeCheck.run ? 0 : 1) if $PROGRAM_NAME == __FILE__
