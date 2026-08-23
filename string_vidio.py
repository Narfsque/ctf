from pathlib import Path
import hashlib
import pefile

src = Path('/home/ubuntu/upload/MatematikaMenyenangkanBukan(1).exe')
out = Path('/home/ubuntu/pe_resources')
out.mkdir(exist_ok=True)
pe = pefile.PE(str(src), fast_load=False)
print('MACHINE', hex(pe.FILE_HEADER.Machine))
print('ENTRYPOINT_RVA', hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
print('IMAGEBASE', hex(pe.OPTIONAL_HEADER.ImageBase))
print('SECTIONS')
for s in pe.sections:
    name = s.Name.rstrip(b'\0').decode('latin1', 'replace')
    print(name, 'raw', hex(s.PointerToRawData), hex(s.SizeOfRawData), 'virt', hex(s.VirtualAddress), hex(s.Misc_VirtualSize), 'entropy', round(s.get_entropy(), 3))
print('OVERLAY_OFFSET', pe.get_overlay_data_start_offset())
if pe.get_overlay_data_start_offset() is not None:
    overlay = pe.get_overlay()
    p = out / 'overlay.bin'
    p.write_bytes(overlay)
    print('OVERLAY', len(overlay), hashlib.sha256(overlay).hexdigest())
print('RESOURCES')
if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
    for type_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        tname = str(type_entry.name) if type_entry.name else str(type_entry.id)
        if not hasattr(type_entry, 'directory'): continue
        for name_entry in type_entry.directory.entries:
            nname = str(name_entry.name) if name_entry.name else str(name_entry.id)
            if not hasattr(name_entry, 'directory'): continue
            for lang_entry in name_entry.directory.entries:
                if not hasattr(lang_entry, 'data'): continue
                data = pe.get_data(lang_entry.data.struct.OffsetToData, lang_entry.data.struct.Size)
                fn = out / f'{tname}_{nname}_{lang_entry.id}.bin'
                fn.write_bytes(data)
                print(tname, nname, lang_entry.id, len(data), fn.name, hashlib.sha256(data).hexdigest())
else:
    print('NONE')

