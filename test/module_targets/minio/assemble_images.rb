# frozen_string_literal: true

require_relative 'support'

module MinioTarget
  # Pure import prepares ignored contexts; the explicit assembly mode uses Docker.
  class RuntimeAssembly < Operation
    # @param build_directory [String] complete compiler evidence directory
    # @return [String] prepared receipt path; executes no binary or Docker command
    def self.import(build_directory)
      verified = VerifiedBuild.new(build_directory).verify
      output = File.join(OUTPUT, 'imports', SecureRandom.hex(8))
      FileUtils.mkdir_p(output, mode: 0o700)
      contexts = %w[vulnerable fixed].to_h do |profile|
        path = File.join(output, profile)
        FileUtils.mkdir_p(path)
        %w[home drive].each { |name| FileUtils.mkdir_p(File.join(path, name), mode: 0o750) }
        { 'mc' => 'client', 'minio' => profile }.each do |name, component|
          source = File.join(verified.fetch('components').fetch(component).fetch('directory'), 'binary')
          destination = File.join(path, name)
          FileUtils.cp(source, destination)
          File.chmod(0o755, destination)
        end
        FileUtils.cp(File.join(DIRECTORY, 'Dockerfile'), path)
        File.write(File.join(path, 'provenance.json'), JSON.pretty_generate(verified) + "\n")
        digests = Dir[File.join(path, '*')].select { |file| File.file?(file) }.to_h { |file| [File.basename(file), Digest::SHA256.file(file).hexdigest] }
        [profile, { 'directory' => path, 'files' => digests }]
      end
      receipt = { 'kind' => 'minio-verified-import/v1', 'build' => verified, 'contexts' => contexts, 'inputs_sha256' => MinioTarget.inputs }
      path = File.join(output, 'import.json')
      File.write(path, JSON.pretty_generate(receipt) + "\n")
      path
    end

    # @param path [String] prepared import receipt
    # @return [Hash] conserved context and source provenance; no binary execution
    def self.verify_import(path)
      receipt = JSON.parse(File.read(path))
      raise Error, 'Import source inputs changed; import again explicitly' unless receipt['kind'] == 'minio-verified-import/v1' && receipt['inputs_sha256'] == MinioTarget.inputs

      actual = VerifiedBuild.new(receipt.fetch('build').fetch('source')).verify
      raise Error, 'The imported source-build receipt changed' unless actual == receipt['build']

      receipt.fetch('contexts').each do |profile, context|
        raise Error, 'Unknown runtime profile' unless %w[vulnerable fixed].include?(profile)

        expected_files = {
          'mc' => actual.fetch('components').fetch('client').fetch('sha256'),
          'minio' => actual.fetch('components').fetch(profile).fetch('sha256'),
          'Dockerfile' => Digest::SHA256.file(File.join(DIRECTORY, 'Dockerfile')).hexdigest,
          'provenance.json' => Digest::SHA256.hexdigest(JSON.pretty_generate(actual) + "\n")
        }
        raise Error, 'Context digests differ from the verified source build/recipe' unless context.fetch('files') == expected_files

        context.fetch('files').each do |name, sha|
          raise Error, 'Unexpected context filename' unless %w[mc minio Dockerfile provenance.json].include?(name)

          file = File.join(context.fetch('directory'), name)
          raise Error, "Runtime context changed: #{profile}/#{name}" unless File.file?(file) && !File.symlink?(file) && Digest::SHA256.file(file).hexdigest == sha
          raise Error, "Runtime binary mode differs: #{name}" if %w[mc minio].include?(name) && (File.stat(file).mode & 0o777) != 0o755
        end
        expected_names = %w[Dockerfile drive home mc minio provenance.json]
        raise Error, 'Unexpected runtime context input' unless Dir.children(context.fetch('directory')).sort == expected_names

        empty = %w[home drive].all? do |name|
          directory = File.join(context.fetch('directory'), name)
          File.directory?(directory) && !File.symlink?(directory) && Dir.empty?(directory)
        end
        raise Error, 'Runtime COPY directories must remain empty' unless empty

        validate_dockerfile(File.read(File.join(context.fetch('directory'), 'Dockerfile')))
      end
      receipt
    rescue JSON::ParserError, KeyError, Errno::ENOENT => e
      raise Error, "Invalid verified import: #{e.message}"
    end

    # @param text [String] runtime Dockerfile
    # @return [true] a single pinned-input runtime stage containing no execution/frontend
    def self.validate_dockerfile(text)
      raise Error, 'Remote Dockerfile frontends are not part of this assembly' if text.match?(/^\s*#\s*syntax\s*=/i)

      instructions = text.lines.reject { |line| line.strip.empty? || line.lstrip.start_with?('#') }.map { |line| line.split.first.upcase }
      allowed = %w[ARG FROM COPY USER ENV WORKDIR ENTRYPOINT]
      raise Error, 'Assembly must have one runtime stage and no RUN/ADD/ONBUILD' unless instructions.count('FROM') == 1 && (instructions - allowed).empty? && !text.match?(/COPY\s+--from/i)

      true
    end

    # @param text [String] read-only `docker buildx inspect` output without bootstrap
    # @return [Hash] selected built-in builder identity; helper-backed drivers are refused
    def self.docker_builder(text)
      header = text.split(/^Nodes:/, 2).first
      names = header.scan(/^Name:\s+(\S+)\s*$/).flatten
      drivers = header.scan(/^Driver:\s+(\S+)\s*$/).flatten
      unless names.length == 1 && drivers == ['docker'] && names.first.match?(/\A[\w.-]+\z/)
        raise Error, 'Assembly requires the selected built-in docker Buildx driver; no helper will be bootstrapped or builder configuration changed'
      end

      { 'name' => names.first, 'driver' => drivers.first }
    end

    # @param text [String] non-bootstrap inspection of the explicit built-in builder
    # @return [String] its single Docker context endpoint, suitable for read-only engine identity checks
    def self.builder_endpoint(text)
      nodes = text.split(/^Nodes:/, 2).fetch(1, '')
      endpoints = nodes.scan(/^\s*Endpoint:\s+(\S+)\s*$/).flatten
      unless endpoints.length == 1 && endpoints.first.match?(/\A[\w.-]+\z/)
        raise Error, 'Cannot verify the built-in builder against one Docker context endpoint'
      end

      endpoints.first
    end

    # @param path [String] regular verified import receipt
    # @return [Hash] exact receipt bytes, verified return and source/context input digests
    def self.import_state(path)
      raise Error, 'Import receipt must remain a regular file' unless File.file?(path) && !File.symlink?(path)

      initial_sha = Digest::SHA256.file(path).hexdigest
      verified = verify_import(path)
      inputs = MinioTarget.inputs
      inputs[path.delete_prefix("#{ROOT}/")] = initial_sha
      verified.fetch('contexts').each_value do |context|
        context.fetch('files').each do |name, expected|
          file = File.join(context.fetch('directory'), name)
          actual = Digest::SHA256.file(file).hexdigest
          raise Error, "Context changed during verification: #{file}" unless actual == expected

          inputs[file.delete_prefix("#{ROOT}/")] = actual
        end
      end
      raise Error, 'Import receipt changed during verification' unless Digest::SHA256.file(path).hexdigest == initial_sha

      { 'receipt_sha256' => initial_sha, 'verified_import' => verified, 'inputs_sha256' => inputs.sort.to_h }
    end

    def initialize(import_path)
      super('assembly', MinioTarget.assets.fetch('assembly').fetch('seconds'))
      @import_path = File.realpath(import_path)
      @initial_import_state = self.class.import_state(@import_path)
      @import = @initial_import_state.fetch('verified_import')
      @result['operation'] = 'runtime_assembly'
      @result['initial_import_sha256'] = @initial_import_state.fetch('receipt_sha256')
      @result['assembly_inputs_sha256'] = @initial_import_state.fetch('inputs_sha256')
      @result['external_conservation'] = []
    end

    # @return [Boolean] bounded image assembly, no application/container startup
    def run
      passed = perform do
        assert_import_conservation('before-preflight')
        builder = preflight_builder
        image = @assets.fetch('images').fetch('runtime')
        required(['docker', 'pull', '--platform', @assets.fetch('platform'), image.fetch('reference')], 'runtime-pull', timeout: @seconds)
        base = JSON.parse(required(['docker', 'image', 'inspect', image.fetch('reference')], 'runtime-image')).fetch(0)
        raise Error, 'Runtime base config/RootFS differs' unless base['Id'] == image['config_digest'] && base.dig('RootFS', 'Layers') == image['rootfs'] && base['Architecture'] == 'amd64' && base['Os'] == 'linux'

        @result['images'] = {}
        @import.fetch('contexts').each do |profile, context|
          assert_import_conservation("before-build-#{profile}")
          empty_inventory!("before-assemble-#{profile}")
          assembly = @assets.fetch('assembly')
          server = @assets.fetch('sources').fetch(profile)
          client = @assets.fetch('sources').fetch('client')
          labels = {
            'org.opencontainers.image.source' => server.fetch('repository'), 'org.opencontainers.image.revision' => server.fetch('commit'),
            'module-target.minio.server-sha256' => server.fetch('reference').fetch('binary_sha256'),
            'module-target.minio.mc-sha256' => client.fetch('reference').fetch('binary_sha256')
          }
          name = MinioTarget.image_name(profile)
          args = [
            'docker', '--context', builder.fetch('endpoint'), 'buildx', 'build', '--builder', builder.fetch('name'), '--platform', @assets.fetch('platform'), '--pull=false', '--network', 'none',
            '--build-arg', "RUNTIME_IMAGE=#{image.fetch('reference')}", '--build-arg', "APP_UID=#{assembly.fetch('uid')}",
            '--build-arg', "APP_GID=#{assembly.fetch('gid')}", '--tag', name
          ]
          args += labels.flat_map { |key, value| ['--label', "#{key}=#{value}"] }
          required(args + [context.fetch('directory')], "assemble-#{profile}", timeout: @seconds)
          actual = JSON.parse(required(['docker', 'image', 'inspect', name], "image-#{profile}")).fetch(0)
          raise Error, 'Assembled runtime labels/base ancestry differ' unless actual.dig('RootFS', 'Layers').first(image.fetch('rootfs').length) == image['rootfs'] && labels.all? { |key, value| actual.dig('Config', 'Labels', key) == value }

          @result['images'][profile] = { 'name' => name, 'id' => actual.fetch('Id'), 'labels' => labels }
        end
        assert_import_conservation('after-both-builds')
        @result['resource_scope'] = 'Runtime COPY/metadata only; no RUN or compiler stage. No BuildKit CPU/memory enforcement claim.'
        @result['status'] = 'passed'
      end
      if passed
        assert_import_conservation('after-capture-and-cleanup')
        @result['import'] = @import_path
        @result['import_sha256'] = @initial_import_state.fetch('receipt_sha256')
        File.write(File.join(@directory, 'result.json'), JSON.pretty_generate(@result) + "\n")
        File.write(File.join(@directory, 'assembly.json'), JSON.pretty_generate(@result) + "\n")
      end
      passed
    rescue Error, SystemCallError => e
      @result['status'] = 'external_inputs_changed'
      @result['error'] = e.message
      @result.delete('import')
      @result.delete('import_sha256')
      File.write(File.join(@directory, 'result.json'), JSON.pretty_generate(@result) + "\n")
      false
    end

    private

    def preflight_builder
      name = @assets.fetch('assembly').fetch('builder')
      text = required(['docker', 'buildx', 'inspect', name], 'builder-inspect')
      builder = self.class.docker_builder(text)
      raise Error, 'Explicit built-in builder identity differs' unless builder.fetch('name') == name

      endpoint = self.class.builder_endpoint(text)
      current_id = required(['docker', 'info', '--format', '{{.ID}}'], 'current-engine-id').strip
      builder_id = required(['docker', '--context', endpoint, 'info', '--format', '{{.ID}}'], 'builder-engine-id').strip
      raise Error, 'Explicit builder endpoint is not the current Docker engine' unless !current_id.empty? && current_id == builder_id

      builder = builder.merge('endpoint' => endpoint, 'current_engine_id' => current_id, 'builder_engine_id' => builder_id)
      @result['selected_builder'] = builder
      builder
    end

    def assert_import_conservation(phase)
      record = { 'phase' => phase, 'current' => false }
      @result['external_inputs_current'] = false
      begin
        current = self.class.import_state(@import_path)
        record['receipt_sha256'] = current.fetch('receipt_sha256')
        record['current'] = current == @initial_import_state
        raise Error, "Assembly import/context inputs changed: #{phase}" unless record['current']

        @result['external_inputs_current'] = true
      rescue Error, SystemCallError => e
        record['error'] = e.message
        raise
      ensure
        @result.fetch('external_conservation') << record
      end
      true
    end

    def capture_before_down
      super
    ensure
      safely('capture-import-conservation') { assert_import_conservation('capture-before-down') }
    end
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    case ARGV
    in ['--import', directory]
      puts MinioTarget::RuntimeAssembly.import(directory)
    in ['--verify-import', path]
      puts JSON.pretty_generate(MinioTarget::RuntimeAssembly.verify_import(path))
    in ['--assemble', path]
      exit(MinioTarget::RuntimeAssembly.new(path).run ? 0 : 1)
    else
      warn 'Usage: assemble_images.rb --import BUILD_DIRECTORY | --verify-import IMPORT_JSON | --assemble IMPORT_JSON'
      exit 2
    end
  rescue MinioTarget::Error, SystemCallError => e
    warn "MinIO artifact setup failed: #{e.message}"
    exit 1
  end
end
