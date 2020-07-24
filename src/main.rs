const PERM_READ: u8 = 1 << 0;
const PERM_WRITE: u8 = 1 << 1;
const PERM_EXEC: u8 = 1 << 2;
const PERM_RAW: u8 = 1 << 3;

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Permissions(u8);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct VirtualAddress(usize);

struct Mmu {
    memory: Vec<u8>,
    permissions: Vec<Permissions>,
    current_alc: VirtualAddress,
}

impl Mmu {
    pub fn new(size: usize) -> Self {
        Self {
            memory: vec![0; size],
            permissions: vec![Permissions(0); size],
            current_alc: VirtualAddress(0x10000),
        }
    }

    pub fn allocate(&mut self, size: usize) -> Option<VirtualAddress> {
        let aligned_size = (size + 0xf) & !0xf;
        let base = self.current_alc;
        if base.0 >= self.memory.len() {
            return None;
        }
        self.current_alc = VirtualAddress(self.current_alc.0.checked_add(aligned_size)?);
        if self.current_alc.0 > self.memory.len() {
            return None;
        }
        self.set_permissons(base, size, Permissions(PERM_RAW | PERM_WRITE));
        Some(base)
    }

    pub fn set_permissons(
        &mut self,
        address: VirtualAddress,
        size: usize,
        permissions: Permissions,
    ) -> Option<()> {
        self.permissions
            .get_mut(address.0..address.0.checked_add(size)?)?
            .iter_mut()
            .for_each(|x| *x = permissions);
        Some(())
    }

    pub fn write_from(&mut self, address: VirtualAddress, buf: &[u8]) -> Option<()> {
        let perms = self
            .permissions
            .get_mut(address.0..address.0.checked_add(buf.len())?)?;
        let mut has_raw = false;
        if !perms.iter().all(|x| {
            has_raw |= (x.0 & PERM_RAW) != 0;
            (x.0 & PERM_WRITE) != 0
        }) {
            return None;
        }

        self.memory
            .get_mut(address.0..address.0.checked_add(buf.len())?)?
            .copy_from_slice(buf);

        if has_raw {
            perms.iter_mut().for_each(|x| {
                if (x.0 & PERM_RAW) != 0 {
                    *x = Permissions(x.0 | PERM_READ);
                }
            })
        }
        Some(())
    }

    pub fn read_into(&self, address: VirtualAddress, buf: &mut [u8]) -> Option<()> {
        let perms = self
            .permissions
            .get(address.0..address.0.checked_add(buf.len())?)?;
        if !perms.iter().all(|x| (x.0 & PERM_READ) != 0) {
            return None;
        }
        buf.copy_from_slice(
            self.memory
                .get(address.0..address.0.checked_add(buf.len())?)?,
        );
        Some(())
    }
}

struct Emulator {
    pub memory: Mmu,
}

impl Emulator {
    pub fn new(size: usize) -> Self {
        Self {
            memory: Mmu::new(size),
        }
    }
}

fn main() {
    let mut emu = Emulator::new(1024 * 1024);

    let tmp = emu.memory.allocate(4096).unwrap();
    emu.memory
        .write_from(VirtualAddress(tmp.0 + 0), b"test")
        .unwrap();

    let mut bytes = [0u8; 4];
    emu.memory.read_into(tmp, &mut bytes).unwrap();
    println!("{:x?}", bytes);
}
