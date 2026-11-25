# Source me: environment for cross-building the Windows x64 (GNU ABI) binaries and the NSIS installer on Linux.
# MINGW_ROOT: a prefix holding mingw-w64 gcc/binutils and nsis (Ubuntu 24.04 packages extracted in user space, see
# docs/status/host-changes.md 2026-11-25), default ~/.local/opt/xroot/usr. The official build is the Windows CI job (MSVC ABI).
MINGW_ROOT="${MINGW_ROOT:-$HOME/.local/opt/xroot/usr}"
export PATH="$HOME/.cargo/bin:$MINGW_ROOT/bin:$PATH"
export CC_x86_64_pc_windows_gnu="$MINGW_ROOT/bin/x86_64-w64-mingw32-gcc-posix"
export CXX_x86_64_pc_windows_gnu="$MINGW_ROOT/bin/x86_64-w64-mingw32-g++-posix"
export AR_x86_64_pc_windows_gnu="$MINGW_ROOT/bin/x86_64-w64-mingw32-ar"
export RC_x86_64_pc_windows_gnu="$MINGW_ROOT/bin/x86_64-w64-mingw32-windres"
export WINDRES="$MINGW_ROOT/bin/x86_64-w64-mingw32-windres"
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="$CC_x86_64_pc_windows_gnu"
export NSISDIR="$MINGW_ROOT/share/nsis"
