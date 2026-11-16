require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/elasticsearch_memory/acceptance'

RSpec.describe 'Native Elasticsearch memory disclosure', acceptance: true, order: :defined do
  include_context 'native Elasticsearch memory target'

  profile = ElasticsearchMemoryProfiles.fetch
  if profile.fetch('mode') == 'affected'
    it 'reports the affected version on two fresh public checks without loot' do
      2.times { esm_check('appears') }
    end

    it 'scans twice and reports the genuine returned backing buffer without loot' do
      2.times { esm_collect }
    end

    it 'dumps exactly the backing buffers from both actual HTTP responses' do
      2.times { esm_collect({ 'ACTION' => 'DUMP' }, dump: true) }
    end

    it 'concatenates two actual disclosures on each repeated dump' do
      2.times { esm_collect({ 'ACTION' => 'DUMP', 'LEAK_COUNT' => 2 }, dump: true, count: 2) }
    end

    if ENV.fetch('ELASTICSEARCH_MEMORY_PROFILE', 'elasticsearch_memory') == 'elasticsearch_memory'
      it 'handles a nonexistent index on both public version checks' do
        2.times { esm_check('unknown', 'TARGETURI' => '/module-target-missing/') }
      end

      it 'handles an actual missing bulk handler without reporting a disclosure' do
        2.times { esm_refuse({ 'TARGETURI' => '/module-target-missing/deep/no-handler/' }) }
      end

      it 'handles an unavailable connection on both entrypoints and on a second execution' do
        socket = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
        socket.bind(Socket.sockaddr_in(0, '127.0.0.1'))
        port = Socket.unpack_sockaddr_in(socket.getsockname).first
        2.times do
          esm_check('unknown', 'RPORT' => port, 'HttpClientTimeout' => 1)
          esm_refuse({ 'RPORT' => port, 'HttpClientTimeout' => 1 }, failure: true, http_status: nil)
        end
      ensure
        socket&.close
      end

      it 'continues from an unreachable host to the live host on repeated scanner checks and runs' do
        options = { 'RHOSTS' => '127.0.0.2 127.0.0.1', 'THREADS' => 1, 'HttpClientTimeout' => 1 }
        2.times do
          esm_check('appears', options)
          esm_collect(options)
        end
      end
    end

    if profile.fetch('security')
      %w[writer reader limited].each do |kind|
        it "exercises the actual #{kind} account on repeated checks, scans and dumps" do
          options = { 'USERNAME' => "module_#{kind}", 'PASSWORD' => 'module-target-password' }
          2.times do
            esm_check(kind == 'limited' ? 'unknown' : 'appears', options)
            esm_collect(options)
            esm_collect(options.merge('ACTION' => 'DUMP'), dump: true)
          end
        end
      end

      { 'anonymous' => { 'USERNAME' => '', 'PASSWORD' => '' }, 'incorrect password' => { 'USERNAME' => 'module_writer', 'PASSWORD' => 'incorrect-password' } }.each do |name, options|
        it "rejects #{name} twice without loot or vulnerability reports" do
          2.times do
            esm_check('unknown', options)
            esm_refuse(options, failure: true, http_status: 401)
          end
        end
      end
    end
  else
    it 'does not label the fixed or unrelated target as affected on either check' do
      2.times { esm_check(profile.fetch('mode') == 'fixed' ? 'safe' : 'unknown') }
    end

    it 'does not report a disclosure or save loot on either scan' do
      2.times { esm_refuse({}, failure: profile.fetch('mode') == 'unrelated') }
    end

    it 'does not report a disclosure or save loot on either dump' do
      2.times { esm_refuse({ 'ACTION' => 'DUMP' }, failure: profile.fetch('mode') == 'unrelated') }
    end

    if profile.fetch('mode') == 'fixed'
      it 'handles absent backing buffers twice per repeated dump' do
        2.times { esm_refuse({ 'ACTION' => 'DUMP', 'LEAK_COUNT' => 2 }) }
      end
    end
  end
end
