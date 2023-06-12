# notes on network security
# overview
1. symmetric/ asymmetric encryption, hash, digital signatures
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
print("plain_len = " + str(plain_len))

if plain_len  % 8 != 0:
    to_add =  (plain_len // 8) * 8 + 8 - plain_len
    print("to_add = " + str(to_add))
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

2. explanations and examples on DH and RSA key exchange
3. WEP WPA
4. kerberos
5. PGP
6. SSL/ TLS (security at transport layer)


7. MiTM (man in the middle) attacks and examples
8. evil twin attacks
9. IPSec (security at network layer)
10. 802.1x (data link layer) and attacks on data link layer (MAC spoofing, ARP spoofing, VLAN hopping, switch poisoning attack)
11. firewalls and IDS
12. DNS security
13. attacks on DNS (DNS hijacking, DNS spoofing, DNS exfiltration, DNS amplification attack, DoS, DDoS)
14. broadcast security
15. distributed energy resource
16. zero trust architecture


