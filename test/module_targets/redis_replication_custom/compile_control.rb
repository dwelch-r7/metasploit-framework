# frozen_string_literal: true

require 'base64'
require 'digest'
require 'erb'
require 'fileutils'
require 'open3'
require 'msf/base/simple/buffer'

# Compiles only inside the task-owned SDK overlay, independently of the owner.
module RedisCompiledControl
  def self.sdk
    File.join(Msf::Config.data_directory, 'exploits', 'redis')
  end

  def self.text(artifacts)
    FileUtils.cp('test/module_targets/redis_replication_custom/native_text.c', File.join(sdk, 'module.c'))
    build(artifacts, 'native-text')
  end

  def self.raw(artifacts, encoded)
    bytes = Base64.strict_decode64(encoded)
    buf = Msf::Simple::Buffer.transform(bytes, 'c', 'buf')
    context = Object.new
    context.instance_variable_set(:@module_init_name, 'mcvnativeraw')
    context.instance_variable_set(:@module_cmd, 'mcv.native')
    template = File.read(File.join(sdk, 'module.erb'))
    File.write(File.join(sdk, 'module.c'), ERB.new(template).result(context.instance_eval { binding }))
    build(artifacts, 'native-raw').merge(raw_sha256: Digest::SHA256.hexdigest(bytes))
  end

  def self.build(artifacts, name)
    log = String.new
    [['make', '-C', File.join(sdk, 'rmutil'), 'clean'], ['make', '-C', sdk, 'clean'], ['make', '-C', sdk]].each do |argv|
      stdout, stderr, status = Open3.capture3(*argv)
      log << argv.inspect << "\n" << stdout << stderr
      File.write(File.join(artifacts, name + '-build.log'), log)
      raise "Native SDK build failed: #{argv.inspect}" unless status.success?
    end
    capture(artifacts, name)
  end

  def self.capture(artifacts, name)
    files = %w[module.c module.so].to_h do |file|
      source = File.join(sdk, file)
      destination = File.join(artifacts, name + '-' + file)
      FileUtils.cp(source, destination)
      [file, { path: destination, sha256: Digest::SHA256.file(source).hexdigest }]
    end
    { files: files, path: files.fetch('module.so').fetch(:path) }
  end
end
