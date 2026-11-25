# Checked by Steep, never executed. Keep ordinary prose mentioning untyped legal.
Rex::Ntpath.as_ntpath(Pathname.new('a/b')).upcase
Rex::Version.new(nil)
Rex::Parser::Ini.from_s('[group]').add_group('group')['key'] = 'value'
Rex::Parser::Ini.new(Pathname.new('config.ini'))
Rex::Proto::MsTds::MsTdsLogin7Password.encode('password').bytes
uuid = '12345778-1234-abcd-ef00-0123456789ac'
packet, context = Rex::Proto::DCERPC::Packet.make_bind(uuid, '1.0')
packet.bytesize
context.zero?
Rex::Proto::DCERPC::Packet.make_request('7', 'stub', 2).each(&:bytesize)
Rex::Proto::DCERPC::UUID.uuid_by_name('SAMR')&.upcase

# A minimal caller supplying the retry mixin's required output method.
class RetryHost
  include Msf::Exploit::Retry
  def vprint_status(message); end
end

RetryHost.new.retry_until_truthy(timeout: 1) { 'ready' }&.upcase
RetryHost.new.poll_until_truthy(timeout: 1, interval: 0.5) { 'ready' }&.upcase
