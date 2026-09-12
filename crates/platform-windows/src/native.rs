// SPDX-License-Identifier: MPL-2.0

use std::ffi::{OsStr, OsString};
use std::io;
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Component, Path, Prefix};
use std::ptr;
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
    FileFsDeviceInformation, NtCreateFile, NtQueryVolumeInformationFile,
};
use windows_sys::Win32::Foundation::{
    ERROR_NO_MORE_FILES, HANDLE, OBJ_DONT_REPARSE, RtlNtStatusToDosError,
    STATUS_REPARSE_POINT_ENCOUNTERED, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Open(io::Error),
    InvalidPath,
    Reparse,
    Cloud,
    UnsupportedVolume,
    VolumeUnknown(io::Error),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub volume_serial: u64,
    pub file_id: [u8; 16],
    pub directory: bool,
    pub reparse: bool,
    pub dataless: bool,
    pub logical_bytes: Option<u64>,
    pub allocated_bytes: Option<u64>,
}

pub struct Entry {
    pub name: OsString,
    pub metadata: Metadata,
}

pub struct Directory {
    handle: OwnedHandle,
    original: Metadata,
    stamp: (i64, i64),
    buffer: Box<[u64; 8192]>,
    offset: Option<usize>,
    started: bool,
    finished: bool,
}

fn cloud(attributes: u32, tag: u32) -> bool {
    attributes
        & (FILE_ATTRIBUTE_OFFLINE
            | FILE_ATTRIBUTE_RECALL_ON_OPEN
            | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)
        != 0
        || tag & !0x0000_f000 == 0x9000_001a
}

fn invalid_data() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid native directory record",
    )
}

fn component_units(name: &OsStr) -> Result<Vec<u16>, Error> {
    let units: Vec<u16> = name.encode_wide().collect();
    if units.is_empty()
        || units == [46]
        || units == [46, 46]
        || units.iter().any(|unit| [0, 47, 58, 92].contains(unit))
    {
        return Err(Error::InvalidPath);
    }
    Ok(units)
}

fn root_units(path: &Path) -> Result<Vec<u16>, Error> {
    let mut components = path.components();
    let drive = match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
            _ => return Err(Error::UnsupportedVolume),
        },
        _ => return Err(Error::InvalidPath),
    };
    if components.next() != Some(Component::RootDir) {
        return Err(Error::InvalidPath);
    }
    let mut units: Vec<u16> = r"\??\".encode_utf16().collect();
    units.extend([u16::from(drive), 58]);
    let mut count = 0;
    for component in components {
        let Component::Normal(name) = component else {
            return Err(Error::InvalidPath);
        };
        units.push(92);
        units.extend(component_units(name)?);
        count += 1;
    }
    if count == 0 {
        return Err(Error::InvalidPath);
    }
    Ok(units)
}

fn open_directory(mut units: Vec<u16>, parent: HANDLE) -> Result<OwnedHandle, Error> {
    let length = units
        .len()
        .checked_mul(2)
        .and_then(|size| u16::try_from(size).ok())
        .ok_or(Error::InvalidPath)?;
    let name = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: units.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent,
        ObjectName: &name,
        Attributes: OBJ_DONT_REPARSE,
        ..Default::default()
    };
    let mut handle = ptr::null_mut();
    let mut status_block = IO_STATUS_BLOCK::default();
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &attributes,
            &mut status_block,
            ptr::null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            ptr::null(),
            0,
        )
    };
    if status == STATUS_REPARSE_POINT_ENCOUNTERED {
        return Err(Error::Reparse);
    }
    if status < 0 {
        return Err(Error::Open(nt_error(status)));
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

fn nt_error(status: i32) -> io::Error {
    io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32)
}

fn basic(handle: HANDLE) -> io::Result<FILE_BASIC_INFO> {
    let mut info = FILE_BASIC_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileBasicInfo,
            ptr::from_mut(&mut info).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(info)
}

fn identity(handle: HANDLE) -> io::Result<FILE_ID_INFO> {
    let mut info = FILE_ID_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            ptr::from_mut(&mut info).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if info.FileId.Identifier == [0; 16] {
        return Err(invalid_data());
    }
    Ok(info)
}

#[repr(C)]
#[derive(Default)]
struct VolumeDevice {
    device_type: u32,
    characteristics: u32,
}

fn validate_volume(handle: HANDLE) -> Result<(), Error> {
    let mut device = VolumeDevice::default();
    let mut status_block = IO_STATUS_BLOCK::default();
    let status = unsafe {
        NtQueryVolumeInformationFile(
            handle,
            &mut status_block,
            ptr::from_mut(&mut device).cast(),
            size_of::<VolumeDevice>() as u32,
            FileFsDeviceInformation,
        )
    };
    if status < 0 {
        return Err(Error::VolumeUnknown(nt_error(status)));
    }
    if device.device_type != 7 || device.characteristics & (0x1 | 0x10) != 0 {
        return Err(Error::UnsupportedVolume);
    }
    let mut filesystem = [0u16; 32];
    if unsafe {
        GetVolumeInformationByHandleW(
            handle,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    } == 0
    {
        return Err(Error::VolumeUnknown(io::Error::last_os_error()));
    }
    let end = filesystem
        .iter()
        .position(|unit| *unit == 0)
        .ok_or_else(|| Error::VolumeUnknown(invalid_data()))?;
    if filesystem[..end] != [78, 84, 70, 83] {
        return Err(Error::UnsupportedVolume);
    }
    Ok(())
}

impl Directory {
    pub fn open_root(path: &Path) -> Result<Self, Error> {
        let handle = open_directory(root_units(path)?, ptr::null_mut())?;
        let directory = Self::from_handle(handle)?;
        validate_volume(directory.handle.as_raw_handle())?;
        Ok(directory)
    }

    fn from_handle(handle: OwnedHandle) -> Result<Self, Error> {
        let info = basic(handle.as_raw_handle())?;
        if cloud(info.FileAttributes, 0) {
            return Err(Error::Cloud);
        }
        if info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(Error::Reparse);
        }
        let id = identity(handle.as_raw_handle())?;
        Ok(Self {
            handle,
            original: Metadata {
                volume_serial: id.VolumeSerialNumber,
                file_id: id.FileId.Identifier,
                directory: true,
                reparse: false,
                dataless: false,
                logical_bytes: None,
                allocated_bytes: None,
            },
            stamp: (info.LastWriteTime, info.ChangeTime),
            buffer: Box::new([0; 8192]),
            offset: None,
            started: false,
            finished: false,
        })
    }

    pub fn metadata(&self) -> &Metadata {
        &self.original
    }

    pub fn open_child(&self, name: &OsStr) -> Result<Self, Error> {
        Self::from_handle(open_directory(
            component_units(name)?,
            self.handle.as_raw_handle(),
        )?)
    }

    pub fn unchanged(&self) -> Result<bool, Error> {
        let info = basic(self.handle.as_raw_handle())?;
        let id = identity(self.handle.as_raw_handle())?;
        Ok((info.LastWriteTime, info.ChangeTime) == self.stamp
            && info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
            && !cloud(info.FileAttributes, 0)
            && id.VolumeSerialNumber == self.original.volume_serial
            && id.FileId.Identifier == self.original.file_id)
    }

    pub fn next_entry(&mut self) -> Option<Result<Entry, Error>> {
        if self.finished {
            return None;
        }
        loop {
            if self.offset.is_none() {
                self.buffer.fill(0);
                let class = if self.started {
                    FileIdExtdDirectoryInfo
                } else {
                    FileIdExtdDirectoryRestartInfo
                };
                self.started = true;
                if unsafe {
                    GetFileInformationByHandleEx(
                        self.handle.as_raw_handle(),
                        class,
                        self.buffer.as_mut_ptr().cast(),
                        size_of::<[u64; 8192]>() as u32,
                    )
                } == 0
                {
                    self.finished = true;
                    let error = io::Error::last_os_error();
                    return (error.raw_os_error() != Some(ERROR_NO_MORE_FILES as i32))
                        .then_some(Err(Error::Io(error)));
                }
                self.offset = Some(0);
            }
            let entry = self.parse_entry();
            match entry {
                Ok(entry) if entry.name == "." || entry.name == ".." => continue,
                Ok(entry) => return Some(Ok(entry)),
                Err(error) => {
                    self.finished = true;
                    return Some(Err(error.into()));
                }
            }
        }
    }

    fn parse_entry(&mut self) -> io::Result<Entry> {
        let offset = self.offset.ok_or_else(invalid_data)?;
        let capacity = size_of::<[u64; 8192]>();
        if offset > capacity - size_of::<FILE_ID_EXTD_DIR_INFO>() {
            return Err(invalid_data());
        }
        let bytes = self.buffer.as_ptr().cast::<u8>();
        let record =
            unsafe { ptr::read_unaligned(bytes.add(offset).cast::<FILE_ID_EXTD_DIR_INFO>()) };
        let name_offset = offset_of!(FILE_ID_EXTD_DIR_INFO, FileName);
        let length = record.FileNameLength as usize;
        let end = if record.NextEntryOffset == 0 {
            capacity
        } else {
            offset
                .checked_add(record.NextEntryOffset as usize)
                .filter(|end| *end <= capacity)
                .ok_or_else(invalid_data)?
        };
        if length == 0
            || !length.is_multiple_of(2)
            || length > 65_534
            || record.FileId.Identifier == [0; 16]
            || offset + name_offset + length > end
        {
            return Err(invalid_data());
        }
        let units: Vec<u16> = (0..length / 2)
            .map(|index| unsafe {
                ptr::read_unaligned(bytes.add(offset + name_offset + index * 2).cast::<u16>())
            })
            .collect();
        self.offset = (record.NextEntryOffset != 0).then_some(end);
        let directory = record.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        let reparse = record.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
        let regular = !directory && !reparse;
        let name = OsString::from_wide(&units);
        if name != "." && name != ".." && component_units(&name).is_err() {
            return Err(invalid_data());
        }
        Ok(Entry {
            name,
            metadata: Metadata {
                volume_serial: self.original.volume_serial,
                file_id: record.FileId.Identifier,
                directory,
                reparse,
                dataless: cloud(record.FileAttributes, record.ReparsePointTag),
                logical_bytes: regular
                    .then(|| u64::try_from(record.EndOfFile).ok())
                    .flatten(),
                allocated_bytes: regular
                    .then(|| u64::try_from(record.AllocationSize).ok())
                    .flatten(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_names_reject_devices_streams_and_traversal() {
        for path in [
            r"C:\",
            r"C:relative",
            r"C:\one\..\two",
            r"C:\one:stream",
            r"\\.\C:\one",
            r"\\server\share\one",
        ] {
            assert!(root_units(Path::new(path)).is_err(), "{path:?}");
        }
        assert_eq!(
            root_units(Path::new(r"C:\owned\sample")).unwrap(),
            r"\??\C:\owned\sample".encode_utf16().collect::<Vec<_>>()
        );
        assert_eq!(
            root_units(Path::new(r"\\?\C:\owned\sample")).unwrap(),
            root_units(Path::new(r"C:\owned\sample")).unwrap()
        );
    }

    #[test]
    fn cloud_flags_and_tags_fail_closed() {
        assert!(!cloud(FILE_ATTRIBUTE_DIRECTORY, 0));
        for flag in [
            FILE_ATTRIBUTE_OFFLINE,
            FILE_ATTRIBUTE_RECALL_ON_OPEN,
            FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
        ] {
            assert!(cloud(flag, 0));
        }
        for tag in [0x9000_001a, 0x9000_f01a] {
            assert!(cloud(FILE_ATTRIBUTE_REPARSE_POINT, tag));
        }
    }

    #[test]
    fn native_sparse_allocation_matches_independent_windows_query() {
        use std::io::Write;
        use windows_sys::Win32::System::IO::DeviceIoControl;
        use windows_sys::Win32::System::Ioctl::FSCTL_SET_SPARSE;

        let fixture = tempfile::Builder::new()
            .prefix("sayaka-windows-owned-")
            .tempdir()
            .unwrap();
        std::fs::write(fixture.path().join("owner-marker"), b"owned sparse fixture").unwrap();
        let root = fixture.path().join("scan");
        std::fs::create_dir(&root).unwrap();
        let path = root.join("sparse");
        let mut file = std::fs::File::create(&path).unwrap();
        let mut returned = 0;
        assert_ne!(
            unsafe {
                DeviceIoControl(
                    file.as_raw_handle(),
                    FSCTL_SET_SPARSE,
                    ptr::null(),
                    0,
                    ptr::null_mut(),
                    0,
                    &mut returned,
                    ptr::null_mut(),
                )
            },
            0,
            "sparse fixture setup: {}",
            io::Error::last_os_error()
        );
        file.set_len(1_048_576).unwrap();
        file.write_all(b"owned data").unwrap();
        file.sync_all().unwrap();
        drop(file);
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        wide.push(0);
        let mut high = 0;
        let low = unsafe { GetCompressedFileSizeW(wide.as_ptr(), &mut high) };
        assert_ne!(low, u32::MAX, "allocation query failed");
        let allocated = u64::from(high) << 32 | u64::from(low);
        let mut directory = Directory::open_root(&root).unwrap();
        let entry = directory.next_entry().unwrap().unwrap();
        assert_eq!(entry.name, "sparse");
        assert_eq!(entry.metadata.logical_bytes, Some(1_048_576));
        assert_eq!(entry.metadata.allocated_bytes, Some(allocated));
        assert!(allocated < 1_048_576);
        assert!(directory.next_entry().is_none());
        drop(directory);
        fixture.close().unwrap();
    }
}
