# notes on network security
# overview
## symmetric/ asymmetric encryption, hash, digital signatures
DES encryption and decryption in CBC mode

```
from Crypto.Cipher import DES
import sys
hex_arr = "abcdefABCDEF0123456789"

if len(sys.argv) != 5:
    print("arguments error")
    sys.exit()

if len(sys.argv[1]) != 16 or len(sys.argv[2]) != 16:
    print("length error")
    sys.exit()

for each in sys.argv[2]:
    if not each in hex_arr:
        print(f"{each} is not in {hex_arr}")
        sys.exit()

iv = bytes.fromhex(sys.argv[1])
cbc_key = bytes.fromhex(sys.argv[2])

des1 = DES.new(cbc_key, DES.MODE_CBC, iv)
des2 = DES.new(cbc_key, DES.MODE_CBC, iv)

in_file = sys.argv[3]
out_file = sys.argv[4]

f_in = open(in_file, 'r')
f_out= open(out_file, 'wb')

plain_text = f_in.read()

plain_len = len(plain_text)

if plain_len  % 8 != 0:
    to_add =  (plain_len // 8) * 8 + 8 - plain_len
    plain_text += '\0' * to_add

c_text = des1.encrypt(plain_text.encode("latin-1"))
f_out.write(c_text)
f_out.close()
f_in.close()

# cipher_text = des1.encrypt(plain_text.encode("latin-1"))
msg = des2.decrypt(c_text)
if msg.decode("latin-1") == plain_text:
    print("encryption and decryption has same results")

print('=' * 100)
```
performance measurements
`RSA is assymetric and it's slower than aes/des. `

## explanations and examples on DH and RSA key exchange
## WEP WPA
To check which wireless networks are around: paramater is the name of the wireless interface
`airodump-ng wlan0`
To crack the key based on the collected handshake messages
```
sudo aircrack-ng -w <word dictionary path> -b <BBSID of target AP> ~/*.cap
```
`*.cap` are the files containing the handshake

## kerberos
## PGP
## SSL/ TLS (security at transport layer)
## MiTM (man in the middle) attacks and examples and evil twin attacks
## IPSec (security at network layer)
## 802.1x (data link layer) and attacks on data link layer (MAC spoofing, ARP spoofing, VLAN hopping, switch poisoning attack)
## firewalls and IDS
### snort examples
`log tcp any any -> 192.168.1.0/24 23`
Logs TCP traffic coming from any IP address and any source port to this network where the destination port is 23.

`alert tcp !192.168.1.0/24 any -> 192.168.1.0/24 !:1024`
! is the negation operator, so this rule tells Snort to alert every TCP packets except
(1) if the tcp packet is *from* 192.168.1.0/24 (i.e.: 192.168.1.0 - 192.168.0.255), or 
(2) if the tcp packet is *to* port less than or equal to port 1024 of 192.168.1.0/24

## DNS security
## attacks on DNS (DNS hijacking, DNS spoofing, DNS exfiltration, DNS amplification attack, DoS, DDoS)
## broadcast security
## distributed energy resource
## zero trust architecture


