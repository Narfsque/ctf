from pathlib import Path
import re

path = Path('/home/ubuntu/upload/MatematikaMenyenangkanBukan(1).exe')
data = path.read_bytes()

patterns = {
    'ascii': rb'[	 -~]{6,}',
    'utf16le': rb'(?:[	 -~]\x00){6,}',
}

all_strings = []
for kind, pat in patterns.items():
    for m in re.finditer(pat, data):
        raw = m.group(0)
        text = raw.decode('utf-16le' if kind == 'utf16le' else 'latin1', errors='replace')
        all_strings.append((m.start(), kind, text))

all_strings.sort()
urls = set()
flags = set()
for _, _, text in all_strings:
    for u in re.findall(r'https?://[^\s"\'<>]+', text, flags=re.I):
        urls.add(u.rstrip('.,);]}'))
    for f in re.findall(r'(?i)(?:flag|ctf|key|secret)\{[^\r\n}]{1,200}\}', text):
        flags.add(f)

print('URLS')
for u in sorted(urls):
    print(u)
print('FLAGS')
for f in sorted(flags):
    print(f)
print('INTERESTING_STRINGS')
keywords = re.compile(r'(?i)(youtube|youtu\.be|video|bawang|astronaut|pilot|dokter|flag|ctf|secret|key|http|www\.)')
for off, kind, text in all_strings:
    if keywords.search(text):
        print(f'{off:08x}\t{kind}\t{text}')
print('COUNTS')
print(f'bytes={len(data)} strings={len(all_strings)} urls={len(urls)} flags={len(flags)}')

