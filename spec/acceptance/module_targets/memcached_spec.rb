require 'acceptance_spec_helper'
require 'socket'

RSpec.describe 'Memcached module targets' do
  include_context 'module target'

  { 'legacy' => '1.4.39', 'modern' => '1.6.26' }.each do |service, version|
    context service do
      before do
        expect(memcached_request(service, "version\r\n")).to eq("VERSION #{version}\r\n")
        expect(memcached_request(service, "flush_all\r\n")).to eq("OK\r\n")
      end

      it 'extracts real keys and values using the version-specific enumeration path' do
        value = 'module-target-memcached-value'
        expect(memcached_request(service, "set module-target-key 0 0 #{value.bytesize}\r\n#{value}\r\n")).to eq("STORED\r\n")
        expect(memcached_request(service, "get module-target-key\r\n")).to include(value)
        enumeration = if service == 'modern'
                        memcached_request(service, "lru_crawler metadump all\r\n")
                      else
                        slabs = memcached_request(service, "stats slabs\r\n")
                        slab = slabs[/^STAT (\d+):/, 1]
                        expect(slab).not_to be_nil
                        memcached_request(service, "stats cachedump #{slab} 10\r\n")
                      end
        expect(enumeration).to include('module-target-key')
        output = run_target_module('auxiliary/gather/memcached_extractor', service)
        expect(output).to include("Connected to memcached version #{version}", 'Found 1 keys', 'module-target-key', value)
        expect(output).to include(service == 'modern' ? 'Using lru_crawler' : 'Using cachedump')
      end

      it 'handles a verified empty cache without inventing values' do
        expect(memcached_request(service, "get module-target-key\r\n")).to eq("END\r\n")
        output = run_target_module('auxiliary/gather/memcached_extractor', service)
        expect(output).to include('Found 0 keys')
        expect(output).not_to include('Keys/Values Found')
      end
    end
  end

  # Independent implementation of the target's documented text protocol:
  # https://github.com/memcached/memcached/blob/1.6.26/doc/protocol.txt
  def memcached_request(service, command)
    endpoint = target_endpoint(service)
    Socket.tcp(endpoint.fetch('host'), endpoint.fetch('port'), connect_timeout: 3) do |socket|
      socket.write(command)
      response = +''
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 3
      loop do
        remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
        raise 'Memcached fixture response timed out' unless remaining.positive? && IO.select([socket], nil, nil, remaining)

        response << socket.readpartial(4096)
        break if response.end_with?("END\r\n", "STORED\r\n", "OK\r\n") || response.start_with?('VERSION ')
      end
      response
    end
  end
end
