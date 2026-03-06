from url_canonicalizer import canonicalize

tests = [
    ("Fragment", "http://google.com/#frag"),
    ("Tab/CR", "http://goo\tgle.com/"),
    ("Octal IP", "http://0177.0.0.01/"),
    ("Hex IP", "http://0x7f000001/"),
    ("Int IP", "http://2130706433/"),
    ("3-comp IP", "http://127.0.1/"),
    ("Escape >127", "http://example.com/\xc3\xbcber"),
    ("Path resolve", "http://example.com/a/../b/./c"),
    ("Dots/slashes", "http://example..com//path//"),
    ("Normal", "https://www.example.com"),
]

for name, url in tests:
    print(f"{name:15s}: {canonicalize(url)}")
